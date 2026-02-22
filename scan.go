package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
//   TYPES
// ─────────────────────────────────────────────

type S3ScanResult struct {
	Bucket    string   `json:"bucket"`
	Exists    bool     `json:"exists"`
	Region    string   `json:"region"`
	AuthPerms []string `json:"auth_perms"`
	AllPerms  []string `json:"all_perms"`
	Objects   int      `json:"objects"`
	Size      string   `json:"size"`
	Raw       string   `json:"-"`
}

type S3Object struct {
	Date string `json:"date"`
	Time string `json:"time"`
	Size string `json:"size"`
	Key  string `json:"key"`
}

type CmdResult struct {
	Method     string     `json:"method"`
	Accessible bool       `json:"accessible"`
	Objects    []S3Object `json:"objects,omitempty"`
	Raw        string     `json:"-"`
	Error      string     `json:"error,omitempty"`
}

type WriteTestResult struct {
	UploadAnon bool   `json:"upload_anon"`
	UploadAuth bool   `json:"upload_auth"`
	DeleteAnon bool   `json:"delete_anon"`
	DeleteAuth bool   `json:"delete_auth"`
	ProofFile  string `json:"proof_file,omitempty"`
	ProofLeft  bool   `json:"proof_left"`
}

type BucketResult struct {
	Bucket     string          `json:"bucket"`
	Cloud      string          `json:"cloud"`
	Region     string          `json:"region"`
	HuntState  string          `json:"hunt_state"`
	S3Scan     S3ScanResult    `json:"s3scanner"`
	ListAnon   CmdResult       `json:"list_anon"`
	ListAuth   CmdResult       `json:"list_auth"`
	ACLAnon    CmdResult       `json:"acl_anon"`
	ACLAuth    CmdResult       `json:"acl_auth"`
	PolicyAnon CmdResult       `json:"policy_anon"`
	PolicyAuth CmdResult       `json:"policy_auth"`
	PubBlock   CmdResult       `json:"pub_block"`
	Versioning CmdResult       `json:"versioning"`
	CORSCheck  CmdResult       `json:"cors"`
	WebsiteCfg CmdResult       `json:"website"`
	WriteTest  WriteTestResult `json:"write_test"`
	Findings   []string        `json:"findings"`
}

// Regex helpers used by both AWS and GCP s3scanner parsers
var (
	allUsersRe  = regexp.MustCompile(`AllUsers:\s*\[([^\]]*)\]`)
	authUsersRe = regexp.MustCompile(`AuthUsers:\s*\[([^\]]*)\]`)
	awsRegionRe = regexp.MustCompile(`^(us|eu|ap|sa|ca|me|af|il|mx|us-gov)[-][a-z]+([-][0-9]+)?$`)
)

// ─────────────────────────────────────────────
//   SHELL COMMAND HELPER
// ─────────────────────────────────────────────

func runCmd(args []string, timeout time.Duration) (int, string, string) {
	if len(args) == 0 {
		return -1, "", "empty command"
	}
	cmd := exec.Command(args[0], args[1:]...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return -1, "", err.Error()
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		rc := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				rc = exitErr.ExitCode()
			} else {
				rc = -1
			}
		}
		return rc, stdout.String(), stderr.String()
	case <-time.After(timeout):
		cmd.Process.Kill()
		return -1, "", fmt.Sprintf("command timed out after %s", timeout)
	}
}

// ─────────────────────────────────────────────
//   S3SCANNER WRAPPER (AWS)
// ─────────────────────────────────────────────

func runS3Scanner(bucket string) S3ScanResult {
	logSection(fmt.Sprintf("Phase 2 — S3Scanner: Enumerate [%s]", bucket))
	result := S3ScanResult{Bucket: bucket}

	cmd := []string{"s3scanner", "-bucket", bucket, "-enumerate"}
	logInfo("Running: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 120*time.Second)
	combined := stdout + stderr
	result.Raw = combined

	if rc == -1 && strings.Contains(stderr, "not found") {
		logError("s3scanner not found — install it: go install github.com/sa7mon/S3Scanner@latest")
		return result
	}

	for _, line := range strings.Split(combined, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "exists") || !strings.Contains(line, bucket) {
			continue
		}
		result.Exists = true

		parts := strings.Split(line, "|")
		if len(parts) >= 3 {
			candidate := strings.TrimSpace(parts[2])
			if awsRegionRe.MatchString(candidate) {
				result.Region = candidate
			}
		}

		if m := authUsersRe.FindStringSubmatch(line); len(m) > 1 {
			for _, p := range strings.Split(m[1], ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					result.AuthPerms = append(result.AuthPerms, p)
				}
			}
		}

		if m := allUsersRe.FindStringSubmatch(line); len(m) > 1 {
			for _, p := range strings.Split(m[1], ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					result.AllPerms = append(result.AllPerms, p)
				}
			}
		}

		if m := regexp.MustCompile(`(\d+)\s+objects?\s+\(([^)]+)\)`).FindStringSubmatch(line); len(m) > 2 {
			result.Objects, _ = strconv.Atoi(m[1])
			result.Size = strings.TrimSpace(m[2])
		}

		region := result.Region
		if region == "" {
			region = "unknown"
		}
		logSuccess("Bucket exists  →  Region: %s%s%s", Cyan, region, Reset)
		for _, p := range result.AllPerms {
			logResult("  AllUsers Perm", bucket, p, "")
		}
		for _, p := range result.AuthPerms {
			logResult("  AuthUsers Perm", bucket, p, "")
		}
		if result.Objects > 0 {
			logInfo("Objects: %s%d%s  Size: %s%s%s", Cyan, result.Objects, Reset, Cyan, result.Size, Reset)
		}
		break
	}

	if !result.Exists {
		logWarn("S3Scanner: no existence confirmed for %s", bucket)
	}
	return result
}

// ─────────────────────────────────────────────
//   AWS CLI WRAPPERS
// ─────────────────────────────────────────────

func regionArgs(region string) []string {
	if region != "" {
		return []string{"--region", region}
	}
	return nil
}

func awsListObjects(bucket, region string, anon bool) CmdResult {
	method := "auth"
	label := "Authenticated"
	if anon {
		method = "anon"
		label = "Anonymous"
	}

	logInfo("Trying %s list: s3://%s", label, bucket)
	cmd := []string{"aws", "s3", "ls", "s3://" + bucket, "--recursive"}
	if anon {
		cmd = append(cmd, "--no-sign-request")
	}
	cmd = append(cmd, regionArgs(region)...)
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 60*time.Second)
	result := CmdResult{Method: method}
	combined := stderr + stdout

	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Objects = parseLsOutput(stdout)
		logSuccess("%s LIST SUCCESS — %d object(s)", strings.ToUpper(label), len(result.Objects))
		printObjectList(result.Objects, 20)
	} else {
		result.Error = strings.TrimSpace(combined)
		if strings.Contains(combined, "AccessDenied") {
			logWarn("%s list → ACCESS DENIED", label)
		} else if strings.Contains(combined, "NoSuchBucket") {
			logWarn("Bucket does not exist (NoSuchBucket)")
		} else if strings.Contains(combined, "Unable to locate credentials") || strings.Contains(combined, "ExpiredToken") {
			logWarn("No valid AWS credentials configured")
		} else if result.Error != "" {
			logWarn("%s list failed: %s", label, truncate(result.Error, 120))
		}
	}
	return result
}

func parseLsOutput(output string) []S3Object {
	var objects []S3Object
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			objects = append(objects, S3Object{
				Date: parts[0],
				Time: parts[1],
				Size: parts[2],
				Key:  strings.Join(parts[3:], " "),
			})
		}
	}
	return objects
}

func printObjectList(objects []S3Object, limit int) {
	if Silent {
		return
	}
	for i, obj := range objects {
		if i >= limit {
			logInfo("  ... and %d more objects", len(objects)-limit)
			break
		}
		fmt.Printf("    %s%s %s%s  %s%10s%s  %s%s%s\n",
			Gray, obj.Date, obj.Time, Reset, Cyan, obj.Size, Reset, White, obj.Key, Reset)
	}
}

func awsGetBucketACL(bucket, region string, anon bool) CmdResult {
	method := "Authenticated"
	if anon {
		method = "Anonymous"
	}
	logInfo("%s ACL check: s3://%s", method, bucket)
	cmd := []string{"aws", "s3api", "get-bucket-acl", "--bucket", bucket}
	cmd = append(cmd, regionArgs(region)...)
	if anon {
		cmd = append(cmd, "--no-sign-request")
	}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 30*time.Second)
	result := CmdResult{Method: "acl_" + strings.ToLower(method)}
	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Raw = stdout
		logSuccess("%s ACL read SUCCESS", method)
		printACLJSON(stdout)
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if strings.Contains(result.Error, "AccessDenied") {
			logWarn("%s ACL → ACCESS DENIED", method)
		} else if result.Error != "" {
			logWarn("%s ACL failed: %s", method, truncate(result.Error, 120))
		}
	}
	return result
}

func printACLJSON(raw string) {
	if Silent {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return
	}
	if owner, ok := data["Owner"].(map[string]interface{}); ok {
		fmt.Printf("    %sOwner:%s %v  (%v)\n", Yellow, Reset,
			owner["DisplayName"], truncate(fmt.Sprint(owner["ID"]), 16))
	}
	if grants, ok := data["Grants"].([]interface{}); ok {
		for _, g := range grants {
			grant, ok := g.(map[string]interface{})
			if !ok {
				continue
			}
			perm := fmt.Sprint(grant["Permission"])
			grantee, _ := grant["Grantee"].(map[string]interface{})
			who := fmt.Sprint(grantee["URI"])
			if who == "" || who == "<nil>" {
				who = fmt.Sprint(grantee["DisplayName"])
			}
			fmt.Printf("    %sGRANT%s  %s%-20s%s  %s%s%s\n",
				Green, Reset, Cyan, perm, Reset, White, who, Reset)
		}
	}
}

func awsGetBucketPolicy(bucket, region string, anon bool) CmdResult {
	method := "Authenticated"
	if anon {
		method = "Anonymous"
	}
	logInfo("%s policy check: s3://%s", method, bucket)
	cmd := []string{"aws", "s3api", "get-bucket-policy", "--bucket", bucket}
	cmd = append(cmd, regionArgs(region)...)
	if anon {
		cmd = append(cmd, "--no-sign-request")
	}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 30*time.Second)
	result := CmdResult{Method: "policy_" + strings.ToLower(method)}
	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Raw = stdout
		logSuccess("%s bucket policy read SUCCESS", method)
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if strings.Contains(result.Error, "AccessDenied") {
			logWarn("%s policy → ACCESS DENIED", method)
		} else if strings.Contains(result.Error, "NoSuchBucketPolicy") {
			logWarn("No bucket policy set on %s", bucket)
		} else if result.Error != "" {
			logWarn("%s policy failed: %s", method, truncate(result.Error, 120))
		}
	}
	return result
}

func awsGetPublicAccessBlock(bucket, region string) CmdResult {
	logInfo("Checking public access block config: %s", bucket)
	cmd := []string{"aws", "s3api", "get-public-access-block", "--bucket", bucket}
	cmd = append(cmd, regionArgs(region)...)
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 20*time.Second)
	result := CmdResult{Method: "pub_block"}
	if rc == 0 {
		result.Accessible = true
		result.Raw = stdout
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &data); err == nil {
			if cfg, ok := data["PublicAccessBlockConfiguration"].(map[string]interface{}); ok {
				allBlocked := true
				for _, v := range cfg {
					if v != true {
						allBlocked = false
						break
					}
				}
				if allBlocked {
					logInfo("Public Access Block: ALL BLOCKED (fully hardened)")
				} else {
					logWarn("Public Access Block: PARTIAL/NONE → %v", cfg)
				}
			}
		}
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if strings.Contains(result.Error, "NoSuchPublicAccessBlockConfiguration") {
			logWarn("No public access block configuration set!")
		} else if strings.Contains(result.Error, "AccessDenied") {
			logWarn("Public access block → ACCESS DENIED")
		}
	}
	return result
}

// ─────────────────────────────────────────────
//   AWS BONUS CHECKS
// ─────────────────────────────────────────────

func awsGetVersioning(bucket, region string) CmdResult {
	logInfo("Checking bucket versioning: %s", bucket)
	cmd := []string{"aws", "s3api", "get-bucket-versioning", "--bucket", bucket}
	cmd = append(cmd, regionArgs(region)...)

	rc, stdout, stderr := runCmd(cmd, 20*time.Second)
	result := CmdResult{Method: "versioning"}
	if rc == 0 {
		result.Accessible = true
		result.Raw = stdout
		if strings.Contains(stdout, "Enabled") {
			logInfo("Versioning: %sENABLED%s — old versions of objects may be recoverable", Green, Reset)
		} else if strings.Contains(stdout, "Suspended") {
			logWarn("Versioning: SUSPENDED — was enabled before, old versions may exist")
		} else {
			logInfo("Versioning: not configured")
		}
	} else {
		result.Error = strings.TrimSpace(stderr)
		if strings.Contains(result.Error, "AccessDenied") {
			logWarn("Versioning check → ACCESS DENIED")
		}
	}
	return result
}

func awsGetCORS(bucket, region string) CmdResult {
	logInfo("Checking CORS configuration: %s", bucket)
	cmd := []string{"aws", "s3api", "get-bucket-cors", "--bucket", bucket}
	cmd = append(cmd, regionArgs(region)...)

	rc, stdout, stderr := runCmd(cmd, 20*time.Second)
	result := CmdResult{Method: "cors"}
	if rc == 0 {
		result.Accessible = true
		result.Raw = stdout
		if strings.Contains(stdout, "*") {
			logWarn("CORS: wildcard origin (*) found — potential CORS misconfiguration!")
		} else {
			logInfo("CORS: configured (non-wildcard)")
		}
	} else {
		result.Error = strings.TrimSpace(stderr)
		if strings.Contains(result.Error, "NoSuchCORSConfiguration") {
			logInfo("CORS: no configuration set")
		} else if strings.Contains(result.Error, "AccessDenied") {
			logWarn("CORS check → ACCESS DENIED")
		}
	}
	return result
}

func awsGetWebsite(bucket, region string) CmdResult {
	logInfo("Checking static website hosting: %s", bucket)
	cmd := []string{"aws", "s3api", "get-bucket-website", "--bucket", bucket}
	cmd = append(cmd, regionArgs(region)...)

	rc, stdout, stderr := runCmd(cmd, 20*time.Second)
	result := CmdResult{Method: "website"}
	if rc == 0 {
		result.Accessible = true
		result.Raw = stdout
		logWarn("Static website hosting ENABLED — potential subdomain takeover vector!")
		logInfo("Website URL: http://%s.s3-website.amazonaws.com", bucket)
	} else {
		result.Error = strings.TrimSpace(stderr)
		if strings.Contains(result.Error, "NoSuchWebsiteConfiguration") {
			logInfo("Website hosting: not configured")
		} else if strings.Contains(result.Error, "AccessDenied") {
			logWarn("Website config check → ACCESS DENIED")
		}
	}
	return result
}

// ─────────────────────────────────────────────
//   WRITE / DELETE PERMISSION TEST (AWS)
// ─────────────────────────────────────────────

func awsWriteTest(bucket, region string) WriteTestResult {
	result := WriteTestResult{}
	filename := fmt.Sprintf("secrets%06d.txt", rand.Intn(1000000))
	content := "XACKB was here\n" // base64: WEFDS0Igd2FzIGhlcmUK
	s3Key := filename

	tmpPath := "/tmp/" + filename
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		logWarn("Could not create temp proof file: %v", err)
		return result
	}
	defer os.Remove(tmpPath)

	logInfo("Write test proof file: %s%s%s", Cyan, filename, Reset)

	s3URI := fmt.Sprintf("s3://%s/%s", bucket, s3Key)
	rArgs := regionArgs(region)

	// Upload — Anonymous
	{
		cmd := append([]string{"aws", "s3", "cp", tmpPath, s3URI, "--no-sign-request"}, rArgs...)
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.UploadAnon = true
			logResult("  UPLOAD (anon)", bucket, "WRITE", "cp succeeded without credentials!")
		} else if strings.Contains(stderr, "AccessDenied") {
			logResult("  UPLOAD (anon)", bucket, "ACCESS_DENIED", "")
		} else {
			logResult("  UPLOAD (anon)", bucket, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	// Upload — Authenticated
	if !result.UploadAnon {
		cmd := append([]string{"aws", "s3", "cp", tmpPath, s3URI}, rArgs...)
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.UploadAuth = true
			logResult("  UPLOAD (auth)", bucket, "WRITE", "cp succeeded with credentials!")
		} else if strings.Contains(stderr, "AccessDenied") {
			logResult("  UPLOAD (auth)", bucket, "ACCESS_DENIED", "")
		} else if strings.Contains(stderr, "Unable to locate credentials") {
			logResult("  UPLOAD (auth)", bucket, "ERROR", "no AWS credentials")
		} else {
			logResult("  UPLOAD (auth)", bucket, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	writeSucceeded := result.UploadAnon || result.UploadAuth
	if !writeSucceeded {
		logInfo("Write test: no upload permission — skipping delete test")
		return result
	}

	// Verify upload
	{
		cmd := append([]string{"aws", "s3", "ls", s3URI}, rArgs...)
		if result.UploadAnon {
			cmd = append(cmd, "--no-sign-request")
		}
		rc, stdout, _ := runCmd(cmd, 15*time.Second)
		if rc == 0 && strings.Contains(stdout, filename) {
			logSuccess("Upload verified: %s exists in bucket", filename)
		}
	}

	// Delete — Anonymous
	{
		cmd := append([]string{"aws", "s3", "rm", s3URI, "--no-sign-request"}, rArgs...)
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.DeleteAnon = true
			logResult("  DELETE (anon)", bucket, "WRITE", "rm succeeded without credentials!")
		} else if strings.Contains(stderr, "AccessDenied") {
			logResult("  DELETE (anon)", bucket, "ACCESS_DENIED", "")
		} else {
			logResult("  DELETE (anon)", bucket, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	// Delete — Authenticated
	if !result.DeleteAnon {
		cmd := append([]string{"aws", "s3", "rm", s3URI}, rArgs...)
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.DeleteAuth = true
			logResult("  DELETE (auth)", bucket, "WRITE", "rm succeeded with credentials!")
		} else if strings.Contains(stderr, "AccessDenied") {
			logResult("  DELETE (auth)", bucket, "ACCESS_DENIED", "")
		} else if strings.Contains(stderr, "Unable to locate credentials") {
			logResult("  DELETE (auth)", bucket, "ERROR", "no AWS credentials")
		} else {
			logResult("  DELETE (auth)", bucket, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	// Re-upload proof if deleted
	deleteSucceeded := result.DeleteAnon || result.DeleteAuth
	if deleteSucceeded {
		cmd := append([]string{"aws", "s3", "cp", tmpPath, s3URI}, rArgs...)
		if result.UploadAnon {
			cmd = append(cmd, "--no-sign-request")
		}
		runCmd(cmd, 30*time.Second)
	}
	result.ProofFile = s3Key
	result.ProofLeft = true
	logSuccess("Proof of concept left: s3://%s/%s", bucket, s3Key)

	return result
}

// ─────────────────────────────────────────────
//   DEEP SCAN ROUTER
// ─────────────────────────────────────────────

func deepScan(bucket DiscoveredBucket, cfg Config) BucketResult {
	switch bucket.Cloud {
	case "gcp":
		return gcpDeepScan(bucket, cfg)
	case "azure", "alibaba":
		return discoveryOnlyResult(bucket)
	default:
		return awsDeepScan(bucket, cfg)
	}
}

func discoveryOnlyResult(bucket DiscoveredBucket) BucketResult {
	result := BucketResult{
		Bucket:    bucket.Name,
		Cloud:     bucket.Cloud,
		HuntState: bucket.State,
	}
	logSection(fmt.Sprintf("%s Bucket: %s (discovery only)", strings.ToUpper(bucket.Cloud), bucket.Name))
	logInfo("Deep scan not yet implemented for %s — bucket noted in report", strings.ToUpper(bucket.Cloud))

	if bucket.State == "OPEN" {
		result.Findings = append(result.Findings,
			fmt.Sprintf("%s: Open bucket discovered at %s", strings.ToUpper(bucket.Cloud), bucket.Hostname))
	} else {
		result.Findings = append(result.Findings,
			fmt.Sprintf("%s: Bucket exists at %s (state: %s)", strings.ToUpper(bucket.Cloud), bucket.Hostname, bucket.State))
	}
	return result
}

// ─────────────────────────────────────────────
//   AWS DEEP SCAN
// ─────────────────────────────────────────────

func awsDeepScan(bucket DiscoveredBucket, cfg Config) BucketResult {
	name := bucket.Name
	result := BucketResult{Bucket: name, Cloud: "aws", HuntState: bucket.State}

	if !Silent {
		fmt.Printf("\n%s%s%s%s\n", Bold, Magenta, strings.Repeat("═", 70), Reset)
		fmt.Printf("%s%s  TARGET AWS BUCKET: %s%s\n", Bold, Magenta, name, Reset)
		fmt.Printf("%s%s%s%s\n", Bold, Magenta, strings.Repeat("═", 70), Reset)
	}

	// Phase 2: S3Scanner
	s3data := runS3Scanner(name)
	result.S3Scan = s3data
	if s3data.Region != "" {
		result.Region = s3data.Region
	}

	// Phase 3: AWS CLI
	logSection(fmt.Sprintf("Phase 3 — AWS CLI Deep Enum [%s]", name))
	region := result.Region

	// List objects
	if !Silent {
		fmt.Printf("\n%s  ── Listing Objects (Anonymous) ─────────────────────────────────%s\n", Gray, Reset)
	}
	result.ListAnon = awsListObjects(name, region, true)

	if !Silent {
		fmt.Printf("\n%s  ── Listing Objects (Authenticated) ─────────────────────────────%s\n", Gray, Reset)
	}
	result.ListAuth = awsListObjects(name, region, false)

	// ACL checks
	if !Silent {
		fmt.Printf("\n%s  ── Bucket ACL ───────────────────────────────────────────────────%s\n", Gray, Reset)
	}
	allPerms := s3data.AllPerms
	if contains(allPerms, "READ_ACP") || cfg.SkipPerms {
		result.ACLAnon = awsGetBucketACL(name, region, true)
	}
	result.ACLAuth = awsGetBucketACL(name, region, false)

	// Bucket Policy
	if !Silent {
		fmt.Printf("\n%s  ── Bucket Policy ────────────────────────────────────────────────%s\n", Gray, Reset)
	}
	result.PolicyAnon = awsGetBucketPolicy(name, region, true)
	result.PolicyAuth = awsGetBucketPolicy(name, region, false)

	// Public Access Block
	if !Silent {
		fmt.Printf("\n%s  ── Public Access Block Config ───────────────────────────────────%s\n", Gray, Reset)
	}
	result.PubBlock = awsGetPublicAccessBlock(name, region)

	// AWS Bonus: Versioning, CORS, Website
	if !Silent {
		fmt.Printf("\n%s  ── Bucket Versioning ────────────────────────────────────────────%s\n", Gray, Reset)
	}
	result.Versioning = awsGetVersioning(name, region)

	if !Silent {
		fmt.Printf("\n%s  ── CORS Configuration ──────────────────────────────────────────%s\n", Gray, Reset)
	}
	result.CORSCheck = awsGetCORS(name, region)

	if !Silent {
		fmt.Printf("\n%s  ── Static Website Hosting ──────────────────────────────────────%s\n", Gray, Reset)
	}
	result.WebsiteCfg = awsGetWebsite(name, region)

	// Write/Delete permission test
	if !Silent {
		fmt.Printf("\n%s  ── Write / Delete Permission Test ──────────────────────────────%s\n", Gray, Reset)
	}
	result.WriteTest = awsWriteTest(name, region)

	// Collect findings
	result.Findings = collectFindings(result)
	return result
}

func collectFindings(r BucketResult) []string {
	var f []string
	if r.ListAnon.Accessible {
		f = append(f, fmt.Sprintf("PUBLIC LIST: Anonymous s3 ls succeeded — %d objects exposed", len(r.ListAnon.Objects)))
	}
	if r.ListAuth.Accessible {
		f = append(f, fmt.Sprintf("AUTHENTICATED LIST: Signed s3 ls succeeded — %d objects", len(r.ListAuth.Objects)))
	}
	if r.ACLAnon.Accessible {
		f = append(f, "ACL READ (anonymous): Bucket ACL readable without credentials")
	}
	if r.ACLAuth.Accessible {
		f = append(f, "ACL READ (authenticated): Bucket ACL readable with your creds")
	}
	if r.PolicyAnon.Accessible {
		f = append(f, "POLICY READ (anonymous): Bucket policy readable without creds")
	}
	if r.PolicyAuth.Accessible {
		f = append(f, "POLICY READ (authenticated): Bucket policy readable with creds")
	}
	for _, p := range r.S3Scan.AllPerms {
		f = append(f, "S3SCANNER AllUsers: "+p)
	}
	for _, p := range r.S3Scan.AuthPerms {
		f = append(f, "S3SCANNER AuthUsers: "+p)
	}
	// Bonus checks
	if r.Versioning.Accessible && strings.Contains(r.Versioning.Raw, "Enabled") {
		f = append(f, "VERSIONING: Enabled — old object versions may be recoverable")
	}
	if r.CORSCheck.Accessible && strings.Contains(r.CORSCheck.Raw, "*") {
		f = append(f, "CORS: Wildcard origin (*) — potential CORS misconfiguration")
	}
	if r.WebsiteCfg.Accessible {
		f = append(f, "WEBSITE: Static website hosting enabled — subdomain takeover vector")
	}
	// Write test
	w := r.WriteTest
	if w.UploadAnon {
		f = append(f, "WRITE (anonymous): Upload succeeded without credentials")
	}
	if w.UploadAuth {
		f = append(f, "WRITE (authenticated): Upload succeeded with your creds")
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

// ─────────────────────────────────────────────
//   REPORT
// ─────────────────────────────────────────────

func printBucketSummary(r BucketResult) {
	if Silent {
		return
	}
	logSection(fmt.Sprintf("  Summary — %s [%s]", r.Bucket, strings.ToUpper(r.Cloud)))
	fmt.Printf("  %sBucket:%s   %s%s%s\n", Bold, Reset, Cyan, r.Bucket, Reset)
	fmt.Printf("  %sCloud:%s    %s%s%s\n", Bold, Reset, Cyan, strings.ToUpper(r.Cloud), Reset)
	region := r.Region
	if region == "" {
		region = "n/a"
	}
	fmt.Printf("  %sRegion:%s   %s%s%s\n", Bold, Reset, Cyan, region, Reset)
	fmt.Printf("  %sState:%s    %s\n\n", Bold, Reset, r.HuntState)

	if len(r.Findings) > 0 {
		logWarn("FINDINGS (%d):", len(r.Findings))
		for _, finding := range r.Findings {
			fmt.Printf("    %s▸%s %s\n", Red, Reset, finding)
		}
	} else {
		logSuccess("No exploitable misconfigurations found")
	}
	fmt.Println()
}

func printFinalReport(results []BucketResult, elapsed time.Duration) {
	fmt.Printf("\n%s%s%s%s\n", Cyan, Bold, strings.Repeat("═", 70), Reset)
	fmt.Printf("%s%s  FINAL REPORT  —  Cloud-Could by k3rn3lbr3ach3r%s\n", Cyan, Bold, Reset)
	fmt.Printf("%s%s%s%s\n\n", Cyan, Bold, strings.Repeat("═", 70), Reset)
	fmt.Printf("  Scan duration : %ds\n", int(elapsed.Seconds()))
	fmt.Printf("  Buckets scanned: %d\n", len(results))

	// Per-cloud breakdown
	cloudCounts := make(map[string]int)
	for _, r := range results {
		cloudCounts[r.Cloud]++
	}
	for cloud, n := range cloudCounts {
		fmt.Printf("    %s• %s: %d%s\n", Gray, strings.ToUpper(cloud), n, Reset)
	}
	fmt.Println()

	var critical, medium []struct {
		bucket   string
		cloud    string
		findings []string
	}
	var clean []string

	for _, r := range results {
		if len(r.Findings) == 0 {
			clean = append(clean, fmt.Sprintf("%s [%s]", r.Bucket, strings.ToUpper(r.Cloud)))
			continue
		}
		isCritical := false
		for _, f := range r.Findings {
			fl := strings.ToLower(f)
			if strings.Contains(fl, "public list") || strings.Contains(fl, "anonymous") ||
				strings.Contains(fl, "write") || strings.Contains(fl, "proof") {
				isCritical = true
				break
			}
		}
		entry := struct {
			bucket   string
			cloud    string
			findings []string
		}{r.Bucket, strings.ToUpper(r.Cloud), r.Findings}
		if isCritical {
			critical = append(critical, entry)
		} else {
			medium = append(medium, entry)
		}
	}

	if len(critical) > 0 {
		fmt.Printf("  %s%s[!!!] CRITICAL (%d bucket(s)):%s\n", Red, Bold, len(critical), Reset)
		for _, e := range critical {
			fmt.Printf("        %s▸%s %s%s%s  %s[%s]%s\n", Red, Reset, White, e.bucket, Reset, Gray, e.cloud, Reset)
			for _, f := range e.findings {
				fmt.Printf("            %s→ %s%s\n", Red, f, Reset)
			}
		}
	}
	if len(medium) > 0 {
		fmt.Printf("\n  %s[!] MEDIUM (%d bucket(s)):%s\n", Yellow, len(medium), Reset)
		for _, e := range medium {
			fmt.Printf("        %s▸%s %s%s%s  %s[%s]%s\n", Yellow, Reset, White, e.bucket, Reset, Gray, e.cloud, Reset)
			for _, f := range e.findings {
				fmt.Printf("            %s→ %s%s\n", Yellow, f, Reset)
			}
		}
	}
	if len(clean) > 0 {
		fmt.Printf("\n  %s[✓] CLEAN / NO FINDINGS (%d bucket(s)):%s\n", Green, len(clean), Reset)
		for _, b := range clean {
			fmt.Printf("        %s✓%s %s\n", Green, Reset, b)
		}
	}
	fmt.Printf("\n%s%s%s\n\n", Cyan, strings.Repeat("─", 70), Reset)
}

func saveJSONReport(results []BucketResult, outfile string) {
	report := map[string]interface{}{
		"tool":      "Cloud-Could",
		"author":    "k3rn3lbr3ach3r",
		"version":   "3.0.0",
		"scan_time": time.Now().Format(time.RFC3339),
		"buckets":   results,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logError("Failed to marshal JSON report: %v", err)
		return
	}
	if err := writeFile(outfile, data); err != nil {
		logError("Failed to save report: %v", err)
		return
	}
	logSuccess("JSON report saved: %s", outfile)
}

// ─────────────────────────────────────────────
//   UTILS
// ─────────────────────────────────────────────

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func writeFile(path string, data []byte) error {
	f, err := createFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
