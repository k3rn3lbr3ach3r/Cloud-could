package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

// ─────────────────────────────────────────────
//   TYPES
// ─────────────────────────────────────────────

type DiscoveredBucket struct {
	Name     string
	Hostname string
	Cloud    string // aws, gcp, azure, alibaba
	Service  string // display label
	State    string // OPEN, PRIVATE, CLOSE, UNKNOWN, MANUAL
	Details  []string
}

type CloudEndpoint struct {
	Cloud   string
	Service string
	Domain  string
}

// AWS S3 ACL XML structures
type aclPolicy struct {
	XMLName xml.Name `xml:"AccessControlPolicy"`
	Owner   struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	} `xml:"Owner"`
	ACL struct {
		Grants []aclGrant `xml:"Grant"`
	} `xml:"AccessControlList"`
}

type aclGrant struct {
	Grantee struct {
		Type        string `xml:"type,attr"`
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
		URI         string `xml:"URI"`
	} `xml:"Grantee"`
	Permission string `xml:"Permission"`
}

// Google IAM testPermissions response
type gcpIAMResponse struct {
	Permissions []string `json:"permissions"`
}

// ─────────────────────────────────────────────
//   CLOUD ENDPOINTS
// ─────────────────────────────────────────────

var allEndpoints = []CloudEndpoint{
	// AWS
	{"aws", "AWS Bucket", "s3.amazonaws.com"},
	// GCP
	{"gcp", "GCS Bucket", "storage.googleapis.com"},
	// Azure
	{"azure", "Azure Blob", "blob.core.windows.net"},
	{"azure", "Azure Files", "file.core.windows.net"},
	{"azure", "Azure Tables", "table.core.windows.net"},
	{"azure", "Azure Queues", "queue.core.windows.net"},
	{"azure", "Azure WebApp", "azurewebsites.net"},
	{"azure", "Azure CDN", "azureedge.net"},
	// Alibaba (major regions)
	{"alibaba", "Alibaba Bucket", "oss-cn-hangzhou.aliyuncs.com"},
	{"alibaba", "Alibaba SH", "oss-cn-shanghai.aliyuncs.com"},
	{"alibaba", "Alibaba BJ", "oss-cn-beijing.aliyuncs.com"},
	{"alibaba", "Alibaba SZ", "oss-cn-shenzhen.aliyuncs.com"},
	{"alibaba", "Alibaba HK", "oss-cn-hongkong.aliyuncs.com"},
	{"alibaba", "Alibaba US-W1", "oss-us-west-1.aliyuncs.com"},
	{"alibaba", "Alibaba US-E1", "oss-us-east-1.aliyuncs.com"},
	{"alibaba", "Alibaba AP-SE1", "oss-ap-southeast-1.aliyuncs.com"},
	{"alibaba", "Alibaba AP-SE2", "oss-ap-southeast-2.aliyuncs.com"},
	{"alibaba", "Alibaba AP-NE1", "oss-ap-northeast-1.aliyuncs.com"},
	{"alibaba", "Alibaba AP-S1", "oss-ap-south-1.aliyuncs.com"},
	{"alibaba", "Alibaba EU-C1", "oss-eu-central-1.aliyuncs.com"},
	{"alibaba", "Alibaba EU-W1", "oss-eu-west-1.aliyuncs.com"},
	{"alibaba", "Alibaba ME-E1", "oss-me-east-1.aliyuncs.com"},
}

func filterEndpoints(clouds []string) []CloudEndpoint {
	if len(clouds) == 0 {
		return allEndpoints
	}
	cloudSet := make(map[string]bool)
	for _, c := range clouds {
		cloudSet[strings.ToLower(strings.TrimSpace(c))] = true
	}
	var filtered []CloudEndpoint
	for _, ep := range allEndpoints {
		if cloudSet[ep.Cloud] {
			filtered = append(filtered, ep)
		}
	}
	return filtered
}

// ─────────────────────────────────────────────
//   PERMUTATION GENERATOR
// ─────────────────────────────────────────────

func loadPermutations(baseName, permFile string) []string {
	perms := []string{baseName}

	f, err := os.Open(permFile)
	if err != nil {
		logWarn("Could not open permutations file: %s — using base name only", permFile)
		return perms
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		perms = append(perms,
			baseName+"-"+word,
			baseName+"."+word,
			baseName+word,
			word+"-"+baseName,
			word+"."+baseName,
			word+baseName,
		)
	}
	return perms
}

func loadResolvers(resolverFile string) []string {
	if resolverFile == "" {
		return nil
	}
	f, err := os.Open(resolverFile)
	if err != nil {
		logWarn("Could not open resolvers file: %s — using system DNS", resolverFile)
		return nil
	}
	defer f.Close()

	var resolvers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			resolvers = append(resolvers, line)
		}
	}
	if len(resolvers) > 0 {
		logInfo("Loaded %s%d%s DNS resolvers", Cyan, len(resolvers), Reset)
	}
	return resolvers
}

// buildHTTPClient is now replaced by buildEvasionClient in evasion.go
// This wrapper exists for backward compatibility
func buildHTTPClient(resolvers []string) *http.Client {
	return buildEvasionClient(NewEvasionConfig(), resolvers)
}

// ─────────────────────────────────────────────
//   HUNT JOB
// ─────────────────────────────────────────────

type huntJob struct {
	Name     string
	Endpoint CloudEndpoint
}

// ─────────────────────────────────────────────
//   MULTI-CLOUD BUCKET DISCOVERY
// ─────────────────────────────────────────────

func huntBuckets(names []string, resolvers []string, workers int, endpoints []CloudEndpoint, evasionCfg EvasionConfig) []DiscoveredBucket {
	printPhaseHeader(1, "Multi-Cloud Bucket Discovery")

	// Count how many clouds
	cloudSet := make(map[string]bool)
	for _, ep := range endpoints {
		cloudSet[ep.Cloud] = true
	}
	clouds := make([]string, 0, len(cloudSet))
	for c := range cloudSet {
		clouds = append(clouds, strings.ToUpper(c))
	}

	totalJobs := len(names) * len(endpoints)
	logInfo("Checking %s%d%s permutations x %s%d%s endpoints (%s) = %s%d%s jobs with %s%d%s workers",
		Cyan, len(names), Reset,
		Cyan, len(endpoints), Reset,
		strings.Join(clouds, ","),
		Cyan, totalJobs, Reset,
		Cyan, workers, Reset)

	// Use evasion-aware HTTP client
	client := buildEvasionClient(evasionCfg, resolvers)
	ch := make(chan huntJob, totalJobs)
	for _, name := range names {
		for _, ep := range endpoints {
			ch <- huntJob{Name: name, Endpoint: ep}
		}
	}
	close(ch)

	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []DiscoveredBucket

	// Progress tracker
	progress := NewProgressTracker(totalJobs, "Discovery")

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range ch {
				bucket := checkCloudBucket(client, job.Name, job.Endpoint)
				progress.Increment()

				if bucket.State == "CLOSE" {
					// Print progress periodically
					if !Verbose {
						progress.Print()
					}
					continue
				}

				progress.IncrementFound()
				mu.Lock()
				results = append(results, bucket)
				if Verbose {
					logResult(bucket.Service, bucket.Hostname, bucket.State,
						strings.Join(bucket.Details, " | "))
				} else {
					// Clear progress line and print result
					fmt.Printf("\r%s\r", strings.Repeat(" ", 120))
					logResult(bucket.Service, bucket.Hostname, bucket.State,
						strings.Join(bucket.Details, " | "))
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	progress.Done()

	// Summary by cloud
	counts := make(map[string]int)
	for _, b := range results {
		counts[b.Cloud]++
	}
	for cloud, n := range counts {
		logInfo("  %s%s%s: %s%d%s bucket(s) found", Cyan, strings.ToUpper(cloud), Reset, Cyan, n, Reset)
	}
	logInfo("Total discovery: %s%d%s bucket(s)", Cyan, len(results), Reset)
	return results
}

func checkCloudBucket(client *http.Client, name string, ep CloudEndpoint) DiscoveredBucket {
	hostname := name + "." + ep.Domain
	url := "https://" + hostname + "/"
	bucket := DiscoveredBucket{
		Name:     name,
		Hostname: hostname,
		Cloud:    ep.Cloud,
		Service:  ep.Service,
		State:    "CLOSE",
	}

	resp, err := client.Get(url)
	if err != nil {
		return bucket
	}
	defer resp.Body.Close()
	// Read body (needed to detect InvalidBucketName from Alibaba/others)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(bodyBytes)

	switch {
	case resp.StatusCode == 200:
		bucket.State = "OPEN"
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "application/xml") || strings.Contains(ct, "application/json") {
			bucket.Details = append(bucket.Details, "LIST")
		}
	case resp.StatusCode == 400:
		// Alibaba OSS returns 400 with InvalidBucketName for dotted names
		if strings.Contains(bodyStr, "InvalidBucketName") || strings.Contains(bodyStr, "NoSuchBucket") {
			bucket.State = "CLOSE"
			return bucket
		}
		bucket.State = "PRIVATE"
	case resp.StatusCode == 403 || resp.StatusCode == 401:
		// Check body for NoSuchBucket masquerading as 403
		if strings.Contains(bodyStr, "NoSuchBucket") {
			bucket.State = "CLOSE"
			return bucket
		}
		bucket.State = "PRIVATE"
	case resp.StatusCode == 301 || resp.StatusCode == 302:
		bucket.State = "PRIVATE"
		if region := resp.Header.Get("x-amz-bucket-region"); region != "" {
			bucket.Details = append(bucket.Details, "Region:"+region)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			bucket.Details = append(bucket.Details, "→"+truncateStr(loc, 60))
		}
	case resp.StatusCode == 404:
		bucket.State = "CLOSE"
		return bucket
	case resp.StatusCode >= 500:
		bucket.State = "OPEN"
		bucket.Details = append(bucket.Details, "ServerError")
	default:
		bucket.State = "UNKNOWN"
		bucket.Details = append(bucket.Details, fmt.Sprintf("HTTP_%d", resp.StatusCode))
	}

	// Cloud-specific ACL probes for OPEN buckets
	if bucket.State == "OPEN" {
		switch ep.Cloud {
		case "aws":
			checkAWSACL(client, &bucket)
		case "gcp":
			checkGCPIAM(client, &bucket)
		}
	}

	return bucket
}

func truncateStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// ─────────────────────────────────────────────
//   AWS ACL CHECK (during discovery)
// ─────────────────────────────────────────────

func checkAWSACL(client *http.Client, bucket *DiscoveredBucket) {
	aclURL := fmt.Sprintf("https://%s.s3.amazonaws.com/?acl", bucket.Name)
	resp, err := client.Get(aclURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return
	}

	var acl aclPolicy
	if err := xml.Unmarshal(body, &acl); err != nil {
		return
	}

	rights := make(map[string]string)
	for _, grant := range acl.ACL.Grants {
		var user string
		if grant.Grantee.URI != "" {
			parts := strings.Split(grant.Grantee.URI, "/")
			user = parts[len(parts)-1]
		} else if grant.Grantee.DisplayName != "" {
			user = grant.Grantee.DisplayName
		} else if len(grant.Grantee.ID) > 8 {
			user = grant.Grantee.ID[:8]
		} else {
			user = grant.Grantee.ID
		}

		sym := "?"
		switch grant.Permission {
		case "READ", "READ_ACP":
			sym = "R"
		case "WRITE", "WRITE_ACP":
			sym = "W"
		case "FULL_CONTROL":
			sym = "F"
		}

		if prev, ok := rights[user]; ok {
			if !strings.Contains(prev, sym) {
				rights[user] = prev + sym
			}
		} else {
			rights[user] = sym
		}
	}

	for user, sym := range rights {
		bucket.Details = append(bucket.Details, fmt.Sprintf("%s [%s]", user, sym))
	}
}

// ─────────────────────────────────────────────
//   GCP IAM testPermissions CHECK (during discovery)
// ─────────────────────────────────────────────

func checkGCPIAM(client *http.Client, bucket *DiscoveredBucket) {
	apiURL := fmt.Sprintf("https://www.googleapis.com/storage/v1/b/%s/iam/testPermissions?"+
		"permissions=storage.buckets.delete&"+
		"permissions=storage.buckets.get&"+
		"permissions=storage.buckets.getIamPolicy&"+
		"permissions=storage.buckets.setIamPolicy&"+
		"permissions=storage.buckets.update&"+
		"permissions=storage.objects.create&"+
		"permissions=storage.objects.delete&"+
		"permissions=storage.objects.get&"+
		"permissions=storage.objects.list&"+
		"permissions=storage.objects.update", bucket.Name)

	resp, err := client.Get(apiURL)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return
	}

	var iam gcpIAMResponse
	if err := json.Unmarshal(body, &iam); err != nil {
		return
	}

	if len(iam.Permissions) == 0 {
		return
	}

	rights := ""
	for _, p := range iam.Permissions {
		switch p {
		case "storage.objects.list":
			rights += "L"
		case "storage.objects.get":
			rights += "R"
		case "storage.objects.create", "storage.objects.delete", "storage.objects.update":
			if !strings.Contains(rights, "W") {
				rights += "W"
			}
		case "storage.buckets.setIamPolicy":
			rights += "V"
		}
	}
	if rights != "" {
		bucket.Details = append(bucket.Details, fmt.Sprintf("AllUsers [%s]", rights))
	}
}
