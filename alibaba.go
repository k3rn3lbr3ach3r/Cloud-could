package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

// -----------------------------------------------
//   ALIBABA OSS DEEP SCAN
// -----------------------------------------------

func alibabaDeepScan(bucket DiscoveredBucket, cfg Config) BucketResult {
	name := bucket.Name
	result := BucketResult{
		Bucket:    name,
		Cloud:     "alibaba",
		HuntState: bucket.State,
	}

	// Extract region endpoint from hostname
	endpoint := extractAlibabaEndpoint(bucket.Hostname, name)

	if !Silent {
		fmt.Printf("\n%s%s%s%s\n", Bold, Magenta, strings.Repeat("=", 70), Reset)
		fmt.Printf("%s%s  TARGET ALIBABA OSS BUCKET: %s%s\n", Bold, Magenta, name, Reset)
		fmt.Printf("%s%s  ENDPOINT: %s%s\n", Bold, Magenta, endpoint, Reset)
		fmt.Printf("%s%s%s%s\n", Bold, Magenta, strings.Repeat("=", 70), Reset)
	}

	// Phase 2: Anonymous object listing
	logSection(fmt.Sprintf("Phase 2 -- Alibaba OSS Anonymous Enum [%s]", name))

	if !Silent {
		fmt.Printf("\n%s  -- Listing Objects (Anonymous) -%s\n", Gray, Reset)
	}
	result.ListAnon = alibabaListObjects(name, endpoint)

	// Phase 3: Deep enumeration
	logSection(fmt.Sprintf("Phase 3 -- Alibaba OSS Deep Enum [%s]", name))

	// ACL Check
	if !Silent {
		fmt.Printf("\n%s  -- Bucket ACL -%s\n", Gray, Reset)
	}
	result.ACLAnon = alibabaGetBucketACL(name, endpoint)

	// Bucket Policy
	if !Silent {
		fmt.Printf("\n%s  -- Bucket Policy -%s\n", Gray, Reset)
	}
	result.PolicyAnon = alibabaGetBucketPolicy(name, endpoint)

	// CORS Configuration
	if !Silent {
		fmt.Printf("\n%s  -- CORS Configuration -%s\n", Gray, Reset)
	}
	result.CORSCheck = alibabaGetCORS(name, endpoint)

	// Referer Policy (Hotlink Protection)
	if !Silent {
		fmt.Printf("\n%s  -- Referer Policy (Hotlink Protection) -%s\n", Gray, Reset)
	}
	result.PubBlock = alibabaGetReferer(name, endpoint)

	// Logging Configuration
	if !Silent {
		fmt.Printf("\n%s  -- Logging Configuration -%s\n", Gray, Reset)
	}
	result.Versioning = alibabaGetLogging(name, endpoint)

	// Website Hosting
	if !Silent {
		fmt.Printf("\n%s  -- Static Website Hosting -%s\n", Gray, Reset)
	}
	result.WebsiteCfg = alibabaGetWebsite(name, endpoint)

	// Authenticated enumeration via aliyun CLI
	if !Silent {
		fmt.Printf("\n%s  -- Authenticated Enumeration (aliyun CLI) -%s\n", Gray, Reset)
	}
	result.ListAuth = alibabaListAuth(name, endpoint)

	// Write/Delete Permission Test
	if !Silent {
		fmt.Printf("\n%s  -- Write / Delete Permission Test -%s\n", Gray, Reset)
	}
	result.WriteTest = alibabaWriteTest(name, endpoint)

	// Collect findings
	result.Findings = collectAlibabaFindings(result)
	return result
}

func extractAlibabaEndpoint(hostname, bucketName string) string {
	// hostname format: bucketname.oss-cn-hangzhou.aliyuncs.com
	// We need: oss-cn-hangzhou.aliyuncs.com
	prefix := bucketName + "."
	if strings.HasPrefix(hostname, prefix) {
		return strings.TrimPrefix(hostname, prefix)
	}
	// Default fallback
	return "oss-cn-hangzhou.aliyuncs.com"
}

// -----------------------------------------------
//   ALIBABA OSS XML TYPES
// -----------------------------------------------

type ossListBucketResult struct {
	XMLName  xml.Name    `xml:"ListBucketResult"`
	Name     string      `xml:"Name"`
	Prefix   string      `xml:"Prefix"`
	Contents []ossObject `xml:"Contents"`
}

type ossObject struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	Size         string `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
	ETag         string `xml:"ETag"`
}

type ossACLResult struct {
	XMLName xml.Name `xml:"AccessControlPolicy"`
	Owner   struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	} `xml:"Owner"`
	AccessControlList struct {
		Grant string `xml:"Grant"`
	} `xml:"AccessControlList"`
}

type ossCORSResult struct {
	XMLName   xml.Name      `xml:"CORSConfiguration"`
	CORSRules []ossCORSRule `xml:"CORSRule"`
}

type ossCORSRule struct {
	AllowedOrigin []string `xml:"AllowedOrigin"`
	AllowedMethod []string `xml:"AllowedMethod"`
	AllowedHeader []string `xml:"AllowedHeader"`
	MaxAgeSeconds int      `xml:"MaxAgeSeconds"`
}

type ossRefererResult struct {
	XMLName           xml.Name `xml:"RefererConfiguration"`
	AllowEmptyReferer bool     `xml:"AllowEmptyReferer"`
	RefererList       struct {
		Referers []string `xml:"Referer"`
	} `xml:"RefererList"`
}

type ossLoggingResult struct {
	XMLName        xml.Name `xml:"BucketLoggingStatus"`
	LoggingEnabled struct {
		TargetBucket string `xml:"TargetBucket"`
		TargetPrefix string `xml:"TargetPrefix"`
	} `xml:"LoggingEnabled"`
}

type ossWebsiteResult struct {
	XMLName       xml.Name `xml:"WebsiteConfiguration"`
	IndexDocument struct {
		Suffix string `xml:"Suffix"`
	} `xml:"IndexDocument"`
	ErrorDocument struct {
		Key string `xml:"Key"`
	} `xml:"ErrorDocument"`
}

// -----------------------------------------------
//   ANONYMOUS OBJECT LISTING
// -----------------------------------------------

func alibabaListObjects(bucket, endpoint string) CmdResult {
	logInfo("Anonymous object listing: %s.%s", bucket, endpoint)
	result := CmdResult{Method: "anon"}

	ossURL := fmt.Sprintf("https://%s.%s/?max-keys=100", bucket, endpoint)
	logInfo("GET %s%s%s", Gray, ossURL, Reset)

	client := getHTTPClient()
	resp, err := client.Get(ossURL)
	if err != nil {
		result.Error = err.Error()
		logWarn("Object listing failed: %s", truncate(err.Error(), 80))
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		// Check if it's a valid XML listing or an error
		if strings.Contains(bodyStr, "<ListBucketResult") {
			result.Accessible = true
			result.Raw = bodyStr

			var listResult ossListBucketResult
			if err := xml.Unmarshal(body, &listResult); err == nil {
				for _, obj := range listResult.Contents {
					result.Objects = append(result.Objects, S3Object{
						Key:  obj.Key,
						Size: obj.Size,
						Date: obj.LastModified,
					})
				}
				logSuccess("ANONYMOUS listing SUCCESS -- %d object(s)", len(listResult.Contents))
				printAlibabaObjectList(listResult.Contents, 20)
			} else {
				logSuccess("ANONYMOUS listing returned data (parse error: %v)", err)
			}
		} else if strings.Contains(bodyStr, "AccessDenied") {
			result.Error = "AccessDenied"
			logWarn("Anonymous listing -> ACCESS DENIED")
		} else {
			result.Accessible = true
			result.Raw = bodyStr
			logSuccess("Anonymous request returned HTTP 200 (non-standard response)")
		}
	} else if resp.StatusCode == 403 {
		result.Error = "AccessDenied"
		if strings.Contains(bodyStr, "AccessDenied") {
			logWarn("Anonymous listing -> ACCESS DENIED")
		} else {
			logWarn("Anonymous listing -> HTTP 403")
		}
	} else if resp.StatusCode == 404 {
		result.Error = "NoSuchBucket"
		logWarn("Bucket not found (404)")
	} else {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		logWarn("Anonymous listing returned HTTP %d", resp.StatusCode)
	}

	return result
}

func printAlibabaObjectList(objects []ossObject, limit int) {
	if Silent {
		return
	}
	for i, obj := range objects {
		if i >= limit {
			logInfo("  ... and %d more objects", len(objects)-limit)
			break
		}
		fmt.Printf("    %s%s%s  %s%10s%s  %s%s%s\n",
			Gray, obj.LastModified, Reset,
			Cyan, obj.Size, Reset,
			White, obj.Key, Reset)
	}
}

// -----------------------------------------------
//   BUCKET ACL CHECK
// -----------------------------------------------

func alibabaGetBucketACL(bucket, endpoint string) CmdResult {
	logInfo("Anonymous ACL check: %s", bucket)
	result := CmdResult{Method: "acl_anon"}

	aclURL := fmt.Sprintf("https://%s.%s/?acl", bucket, endpoint)
	logInfo("GET %s%s%s", Gray, aclURL, Reset)

	client := getHTTPClient()
	resp, err := client.Get(aclURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		result.Accessible = true
		result.Raw = bodyStr

		var acl ossACLResult
		if err := xml.Unmarshal(body, &acl); err == nil {
			grant := acl.AccessControlList.Grant
			logSuccess("Bucket ACL readable! Grant: %s%s%s", Cyan, grant, Reset)

			if grant == "public-read" {
				logWarn("ACL: PUBLIC-READ -- anyone can list/read objects!")
			} else if grant == "public-read-write" {
				logWarn("ACL: PUBLIC-READ-WRITE -- anyone can read AND write!")
			} else if grant == "private" {
				logInfo("ACL: private")
			} else {
				logInfo("ACL Grant: %s", grant)
			}

			if acl.Owner.DisplayName != "" || acl.Owner.ID != "" {
				logInfo("Owner: %s (ID: %s)", acl.Owner.DisplayName, truncate(acl.Owner.ID, 16))
			}
		}
	} else if resp.StatusCode == 403 {
		result.Error = "AccessDenied"
		logWarn("ACL check -> ACCESS DENIED")
	} else {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		logWarn("ACL check returned HTTP %d", resp.StatusCode)
	}

	return result
}

// -----------------------------------------------
//   BUCKET POLICY CHECK
// -----------------------------------------------

func alibabaGetBucketPolicy(bucket, endpoint string) CmdResult {
	logInfo("Bucket policy check: %s", bucket)
	result := CmdResult{Method: "policy_anon"}

	policyURL := fmt.Sprintf("https://%s.%s/?policy", bucket, endpoint)
	logInfo("GET %s%s%s", Gray, policyURL, Reset)

	client := getHTTPClient()
	resp, err := client.Get(policyURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		result.Accessible = true
		result.Raw = bodyStr
		logSuccess("Bucket policy readable!")

		// Check for overly permissive policies
		if strings.Contains(bodyStr, "\"Effect\":\"Allow\"") && strings.Contains(bodyStr, "\"*\"") {
			logWarn("Policy contains wildcard Allow (*) -- potentially overly permissive!")
		}
	} else if resp.StatusCode == 404 {
		logInfo("No bucket policy configured")
	} else if resp.StatusCode == 403 {
		result.Error = "AccessDenied"
		logWarn("Policy check -> ACCESS DENIED")
	} else {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return result
}

// -----------------------------------------------
//   CORS CONFIGURATION
// -----------------------------------------------

func alibabaGetCORS(bucket, endpoint string) CmdResult {
	logInfo("CORS configuration check: %s", bucket)
	result := CmdResult{Method: "cors"}

	corsURL := fmt.Sprintf("https://%s.%s/?cors", bucket, endpoint)
	logInfo("GET %s%s%s", Gray, corsURL, Reset)

	client := getHTTPClient()
	resp, err := client.Get(corsURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		result.Accessible = true
		result.Raw = bodyStr

		var cors ossCORSResult
		if err := xml.Unmarshal(body, &cors); err == nil {
			logSuccess("CORS configuration readable! %d rule(s)", len(cors.CORSRules))
			for _, rule := range cors.CORSRules {
				for _, origin := range rule.AllowedOrigin {
					if origin == "*" {
						logWarn("CORS: wildcard origin (*) -- potential misconfiguration!")
					} else {
						logInfo("  CORS origin: %s", origin)
					}
				}
			}
		}
	} else if resp.StatusCode == 404 {
		logInfo("CORS: no configuration set")
	} else if resp.StatusCode == 403 {
		result.Error = "AccessDenied"
		logWarn("CORS check -> ACCESS DENIED")
	}

	return result
}

// -----------------------------------------------
//   REFERER POLICY (HOTLINK PROTECTION)
// -----------------------------------------------

func alibabaGetReferer(bucket, endpoint string) CmdResult {
	logInfo("Referer policy check: %s", bucket)
	result := CmdResult{Method: "referer"}

	refererURL := fmt.Sprintf("https://%s.%s/?referer", bucket, endpoint)
	logInfo("GET %s%s%s", Gray, refererURL, Reset)

	client := getHTTPClient()
	resp, err := client.Get(refererURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		result.Accessible = true
		result.Raw = bodyStr

		var referer ossRefererResult
		if err := xml.Unmarshal(body, &referer); err == nil {
			if referer.AllowEmptyReferer {
				logWarn(
					"Referer policy: ALLOWS empty referer -- hotlink protection can be bypassed!",
				)
			} else {
				logInfo("Referer policy: empty referer blocked")
			}
			if len(referer.RefererList.Referers) == 0 {
				logWarn("Referer whitelist: EMPTY -- no hotlink protection configured!")
			} else {
				logInfo("Referer whitelist: %d domain(s)", len(referer.RefererList.Referers))
				for _, ref := range referer.RefererList.Referers {
					logInfo("  Allowed: %s", ref)
				}
			}
		}
	} else if resp.StatusCode == 403 {
		result.Error = "AccessDenied"
		logWarn("Referer check -> ACCESS DENIED")
	}

	return result
}

// -----------------------------------------------
//   LOGGING CONFIGURATION
// -----------------------------------------------

func alibabaGetLogging(bucket, endpoint string) CmdResult {
	logInfo("Logging configuration check: %s", bucket)
	result := CmdResult{Method: "logging"}

	loggingURL := fmt.Sprintf("https://%s.%s/?logging", bucket, endpoint)

	client := getHTTPClient()
	resp, err := client.Get(loggingURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		result.Accessible = true
		result.Raw = bodyStr

		var logging ossLoggingResult
		if err := xml.Unmarshal(body, &logging); err == nil {
			if logging.LoggingEnabled.TargetBucket != "" {
				logInfo("Logging: ENABLED -> target: %s (prefix: %s)",
					logging.LoggingEnabled.TargetBucket, logging.LoggingEnabled.TargetPrefix)
			} else {
				logWarn("Logging: NOT CONFIGURED -- access logs not being collected!")
			}
		}
	} else if resp.StatusCode == 403 {
		result.Error = "AccessDenied"
		logWarn("Logging check -> ACCESS DENIED")
	}

	return result
}

// -----------------------------------------------
//   STATIC WEBSITE HOSTING
// -----------------------------------------------

func alibabaGetWebsite(bucket, endpoint string) CmdResult {
	logInfo("Static website hosting check: %s", bucket)
	result := CmdResult{Method: "website"}

	websiteURL := fmt.Sprintf("https://%s.%s/?website", bucket, endpoint)

	client := getHTTPClient()
	resp, err := client.Get(websiteURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == 200 {
		result.Accessible = true
		result.Raw = string(body)

		var website ossWebsiteResult
		if err := xml.Unmarshal(body, &website); err == nil {
			logWarn("Static website hosting ENABLED!")
			logInfo("  Index document: %s", website.IndexDocument.Suffix)
			if website.ErrorDocument.Key != "" {
				logInfo("  Error document: %s", website.ErrorDocument.Key)
			}
			// Build the website URL
			region := strings.TrimSuffix(endpoint, ".aliyuncs.com")
			websiteHost := fmt.Sprintf("https://%s.%s.aliyuncs.com/", bucket, region)
			logInfo("  Website URL: %s", websiteHost)
		}
	} else if resp.StatusCode == 404 {
		logInfo("Static website hosting: not configured")
	} else if resp.StatusCode == 403 {
		result.Error = "AccessDenied"
		logWarn("Website check -> ACCESS DENIED")
	}

	return result
}

// -----------------------------------------------
//   AUTHENTICATED LISTING (aliyun CLI)
// -----------------------------------------------

func alibabaListAuth(bucket, endpoint string) CmdResult {
	logInfo("Authenticated listing: %s (via aliyun CLI)", bucket)
	result := CmdResult{Method: "auth"}

	region := strings.TrimSuffix(endpoint, ".aliyuncs.com")

	cmd := []string{
		"aliyun", "oss", "ls", fmt.Sprintf("oss://%s/", bucket),
		"--region", region, "--output-format", "json",
	}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 30*time.Second)

	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Raw = stdout
		logSuccess("Authenticated listing SUCCESS")
		// Count objects from output
		lines := strings.Split(stdout, "\n")
		objCount := 0
		for _, line := range lines {
			if strings.Contains(line, "oss://") {
				objCount++
			}
		}
		if objCount > 0 {
			logInfo("Found %d object(s) via authenticated listing", objCount)
		}
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if strings.Contains(result.Error, "not found") {
			logWarn("aliyun CLI not installed")
		} else if strings.Contains(result.Error, "AccessDenied") || strings.Contains(result.Error, "403") {
			logWarn("Authenticated listing -> ACCESS DENIED")
		} else if strings.Contains(result.Error, "configure") || strings.Contains(result.Error, "credentials") {
			logWarn("Alibaba Cloud CLI not configured (run: aliyun configure)")
		} else if result.Error != "" {
			logWarn("Auth listing failed: %s", truncate(result.Error, 120))
		}
	}

	return result
}

// -----------------------------------------------
//   WRITE / DELETE PERMISSION TEST
// -----------------------------------------------

func alibabaWriteTest(bucket, endpoint string) WriteTestResult {
	result := WriteTestResult{}
	filename := fmt.Sprintf("cloud-could-poc-%06d.txt", rand.Intn(1000000))
	content := "Cloud-Could PoC -- authorized security testing\n"

	tmpPath := "/tmp/" + filename
	if err := os.WriteFile(tmpPath, []byte(content), 0o644); err != nil {
		logWarn("Could not create temp proof file: %v", err)
		return result
	}
	defer os.Remove(tmpPath)

	logInfo("Write test proof file: %s%s%s", Cyan, filename, Reset)

	ossURL := fmt.Sprintf("https://%s.%s/%s", bucket, endpoint, filename)

	// Upload -- Anonymous HTTP PUT
	{
		fileData, _ := os.ReadFile(tmpPath)
		client := getHTTPClient()
		req, err := http.NewRequest("PUT", ossURL, strings.NewReader(string(fileData)))
		if err == nil {
			req.Header.Set("Content-Type", "text/plain")
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 || resp.StatusCode == 201 {
					result.UploadAnon = true
					logResult("  UPLOAD (anon)", bucket, "WRITE",
						"HTTP PUT succeeded without credentials!")
				} else if resp.StatusCode == 403 {
					logResult("  UPLOAD (anon)", bucket, "ACCESS_DENIED", "")
				} else {
					logResult("  UPLOAD (anon)", bucket, "ERROR",
						fmt.Sprintf("HTTP %d", resp.StatusCode))
				}
			}
		}
	}

	// Upload -- Authenticated via aliyun CLI
	if !result.UploadAnon {
		cmd := []string{
			"aliyun", "oss", "cp", tmpPath,
			fmt.Sprintf("oss://%s/%s", bucket, filename),
		}
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.UploadAuth = true
			logResult("  UPLOAD (auth)", bucket, "WRITE", "aliyun oss cp succeeded!")
		} else if strings.Contains(stderr, "AccessDenied") || strings.Contains(stderr, "403") {
			logResult("  UPLOAD (auth)", bucket, "ACCESS_DENIED", "")
		} else if strings.Contains(stderr, "not found") {
			logResult("  UPLOAD (auth)", bucket, "ERROR", "aliyun CLI not installed")
		} else {
			logResult("  UPLOAD (auth)", bucket, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	writeSucceeded := result.UploadAnon || result.UploadAuth
	if !writeSucceeded {
		logInfo("Write test: no upload permission -- skipping delete test")
		return result
	}

	// Verify upload
	{
		client := getHTTPClient()
		resp, err := client.Head(ossURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				logSuccess("Upload verified: %s exists in bucket", filename)
			}
		}
	}

	// Delete -- Anonymous HTTP DELETE
	{
		client := getHTTPClient()
		req, _ := http.NewRequest("DELETE", ossURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 204 || resp.StatusCode == 200 {
				result.DeleteAnon = true
				logResult("  DELETE (anon)", bucket, "WRITE",
					"HTTP DELETE succeeded without credentials!")
			} else if resp.StatusCode == 403 {
				logResult("  DELETE (anon)", bucket, "ACCESS_DENIED", "")
			}
		}
	}

	// Delete -- Authenticated
	if !result.DeleteAnon {
		cmd := []string{
			"aliyun", "oss", "rm",
			fmt.Sprintf("oss://%s/%s", bucket, filename),
		}
		rc, _, stderr := runCmd(cmd, 20*time.Second)
		if rc == 0 {
			result.DeleteAuth = true
			logResult("  DELETE (auth)", bucket, "WRITE", "aliyun oss rm succeeded!")
		} else if strings.Contains(stderr, "AccessDenied") {
			logResult("  DELETE (auth)", bucket, "ACCESS_DENIED", "")
		}
	}

	// Re-upload proof if deleted
	deleteSucceeded := result.DeleteAnon || result.DeleteAuth
	if deleteSucceeded && (result.UploadAnon || result.UploadAuth) {
		fileData, _ := os.ReadFile(tmpPath)
		client := getHTTPClient()
		req, _ := http.NewRequest("PUT", ossURL, strings.NewReader(string(fileData)))
		if req != nil {
			req.Header.Set("Content-Type", "text/plain")
			client.Do(req)
		}
	}

	result.ProofFile = filename
	result.ProofLeft = true
	logSuccess("Proof of concept: %s.%s/%s", bucket, endpoint, filename)

	return result
}

// -----------------------------------------------
//   ALIBABA FINDINGS COLLECTION
// -----------------------------------------------

func collectAlibabaFindings(r BucketResult) []string {
	var f []string

	if r.ListAnon.Accessible {
		f = append(
			f,
			fmt.Sprintf("PUBLIC LIST: Anonymous object listing succeeded -- %d objects exposed",
				len(r.ListAnon.Objects)),
		)
	}
	if r.ListAuth.Accessible {
		f = append(f, "AUTHENTICATED LIST: aliyun CLI listing succeeded")
	}
	if r.ACLAnon.Accessible {
		if strings.Contains(r.ACLAnon.Raw, "public-read-write") {
			f = append(f, "ACL: PUBLIC-READ-WRITE -- anyone can read and write to this bucket!")
		} else if strings.Contains(r.ACLAnon.Raw, "public-read") {
			f = append(f, "ACL: PUBLIC-READ -- anyone can read objects from this bucket")
		}
		f = append(f, "ACL READ: Bucket ACL readable without authentication")
	}
	if r.PolicyAnon.Accessible {
		f = append(f, "POLICY READ: Bucket policy readable without authentication")
		if strings.Contains(r.PolicyAnon.Raw, "\"*\"") {
			f = append(f, "POLICY: Contains wildcard Allow (*) -- overly permissive!")
		}
	}
	if r.CORSCheck.Accessible && strings.Contains(r.CORSCheck.Raw, "*") {
		f = append(f, "CORS: Wildcard origin (*) -- potential CORS misconfiguration")
	}
	if r.PubBlock.Accessible {
		if strings.Contains(r.PubBlock.Raw, "AllowEmptyReferer") &&
			strings.Contains(r.PubBlock.Raw, "true") {
			f = append(f, "REFERER: Empty referer allowed -- hotlink protection bypassable")
		}
	}
	if r.Versioning.Accessible {
		if !strings.Contains(r.Versioning.Raw, "TargetBucket") ||
			strings.Contains(r.Versioning.Raw, "<TargetBucket/>") ||
			strings.Contains(r.Versioning.Raw, "<TargetBucket></TargetBucket>") {
			f = append(f, "LOGGING: Access logging not configured!")
		}
	}
	if r.WebsiteCfg.Accessible {
		f = append(f, "WEBSITE: Static website hosting enabled")
	}

	// Write test
	w := r.WriteTest
	if w.UploadAnon {
		f = append(f, "WRITE (anonymous): Object upload succeeded without credentials")
	}
	if w.UploadAuth {
		f = append(f, "WRITE (authenticated): Object upload succeeded with your creds")
	}
	if w.DeleteAnon {
		f = append(f, "DELETE (anonymous): Object deletion succeeded without credentials")
	}
	if w.DeleteAuth {
		f = append(f, "DELETE (authenticated): Object deletion succeeded with your creds")
	}
	if w.ProofLeft {
		f = append(f, fmt.Sprintf("PROOF OF CONCEPT: %s left in bucket as evidence", w.ProofFile))
	}

	return f
}

// -----------------------------------------------
//   ALIBABA HMAC HELPER (for future signed requests)
// -----------------------------------------------

func alibabaHMACSHA1(key, data string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
