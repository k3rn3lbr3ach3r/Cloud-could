package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
//   GCP DEEP SCAN (gsutil + s3scanner + IAM)
// ─────────────────────────────────────────────

func gcpDeepScan(bucket DiscoveredBucket, cfg Config) BucketResult {
	name := bucket.Name
	result := BucketResult{
		Bucket:    name,
		HuntState: bucket.State,
		Cloud:     "gcp",
	}

	if !Silent {
		fmt.Printf("\n%s%s%s%s\n", Bold, Magenta, strings.Repeat("═", 70), Reset)
		fmt.Printf("%s%s  TARGET GCS BUCKET: %s%s\n", Bold, Magenta, name, Reset)
		fmt.Printf("%s%s%s%s\n", Bold, Magenta, strings.Repeat("═", 70), Reset)
	}

	// Phase 2: S3Scanner with -provider gcp
	result.S3Scan = runS3ScannerGCP(name)

	// Phase 3: gsutil deep enum
	logSection(fmt.Sprintf("Phase 3 — gsutil Deep Enum [%s]", name))

	gsURI := "gs://" + name

	// List objects — anonymous (unauthenticated)
	if !Silent {
		fmt.Printf("\n%s  ── Listing Objects (Anonymous) ─────────────────────────────────%s\n", Gray, Reset)
	}
	result.ListAnon = gsutilList(name, gsURI, true)

	// List objects — authenticated
	if !Silent {
		fmt.Printf("\n%s  ── Listing Objects (Authenticated) ─────────────────────────────%s\n", Gray, Reset)
	}
	result.ListAuth = gsutilList(name, gsURI, false)

	// IAM Policy check
	if !Silent {
		fmt.Printf("\n%s  ── GCS IAM Policy ──────────────────────────────────────────────%s\n", Gray, Reset)
	}
	result.ACLAnon = gsutilIAM(name, true)
	result.ACLAuth = gsutilIAM(name, false)

	// Write/Delete permission test
	if !Silent {
		fmt.Printf("\n%s  ── Write / Delete Permission Test ──────────────────────────────%s\n", Gray, Reset)
	}
	result.WriteTest = gcpWriteTest(name)

	// Collect findings
	result.Findings = collectGCPFindings(result)
	return result
}

// ─────────────────────────────────────────────
//   S3SCANNER FOR GCP
// ─────────────────────────────────────────────

func runS3ScannerGCP(bucket string) S3ScanResult {
	logSection(fmt.Sprintf("Phase 2 — S3Scanner (GCP): Enumerate [%s]", bucket))
	result := S3ScanResult{Bucket: bucket}

	cmd := []string{"s3scanner", "-bucket", bucket, "-enumerate", "-provider", "gcp"}
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
		logSuccess("GCS Bucket exists: %s%s%s", Cyan, bucket, Reset)

		// Parse AllUsers/AuthUsers permissions if present
		if m := allUsersRe.FindStringSubmatch(line); len(m) > 1 {
			for _, p := range strings.Split(m[1], ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					result.AllPerms = append(result.AllPerms, p)
				}
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

		for _, p := range result.AllPerms {
			logResult("  AllUsers Perm", bucket, p, "")
		}
		for _, p := range result.AuthPerms {
			logResult("  AuthUsers Perm", bucket, p, "")
		}
		break
	}

	if !result.Exists {
		logWarn("S3Scanner (GCP): no existence confirmed for %s", bucket)
	}
	return result
}

// ─────────────────────────────────────────────
//   gsutil LIST
// ─────────────────────────────────────────────

func gsutilList(bucket, gsURI string, anon bool) CmdResult {
	method := "auth"
	label := "Authenticated"
	if anon {
		method = "anon"
		label = "Anonymous"
	}

	logInfo("Trying %s list: %s", label, gsURI)

	var cmd []string
	if anon {
		// Unauthenticated: override credentials to empty
		cmd = []string{"gsutil", "-o", "Credentials:gs_service_key_file=", "ls", "-r", gsURI + "/**"}
	} else {
		cmd = []string{"gsutil", "ls", "-r", gsURI + "/**"}
	}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 60*time.Second)
	result := CmdResult{Method: method}
	combined := stderr + stdout

	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Objects = parseGsutilLsOutput(stdout)
		logSuccess("%s LIST SUCCESS — %d object(s)", strings.ToUpper(label), len(result.Objects))
		printGsutilObjectList(result.Objects, 20)
	} else {
		result.Error = strings.TrimSpace(combined)
		if strings.Contains(combined, "AccessDeniedException") || strings.Contains(combined, "403") {
			logWarn("%s list → ACCESS DENIED", label)
		} else if strings.Contains(combined, "BucketNotFoundException") || strings.Contains(combined, "404") {
			logWarn("Bucket does not exist (404)")
		} else if strings.Contains(combined, "No URLs matched") {
			logWarn("%s list → empty bucket or no access", label)
		} else if result.Error != "" {
			logWarn("%s list failed: %s", label, truncate(result.Error, 120))
		}
	}
	return result
}

func parseGsutilLsOutput(output string) []S3Object {
	var objects []S3Object
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, "/:") || strings.HasPrefix(line, "TOTAL:") {
			continue
		}
		// gsutil ls -r output: just paths (gs://bucket/key) or with -l has size/date
		if strings.HasPrefix(line, "gs://") {
			parts := strings.SplitN(line, "/", 4)
			key := ""
			if len(parts) >= 4 {
				key = parts[3]
			}
			objects = append(objects, S3Object{Key: key})
		} else {
			// -l format: SIZE DATE TIME gs://path
			fields := strings.Fields(line)
			if len(fields) >= 4 && strings.HasPrefix(fields[len(fields)-1], "gs://") {
				gsPath := fields[len(fields)-1]
				pathParts := strings.SplitN(gsPath, "/", 4)
				key := ""
				if len(pathParts) >= 4 {
					key = pathParts[3]
				}
				objects = append(objects, S3Object{
					Size: fields[0],
					Date: fields[1],
					Time: fields[2],
					Key:  key,
				})
			}
		}
	}
	return objects
}

func printGsutilObjectList(objects []S3Object, limit int) {
	if Silent {
		return
	}
	for i, obj := range objects {
		if i >= limit {
			logInfo("  ... and %d more objects", len(objects)-limit)
			break
		}
		if obj.Size != "" {
			fmt.Printf("    %s%s %s%s  %s%10s%s  %s%s%s\n",
				Gray, obj.Date, obj.Time, Reset, Cyan, obj.Size, Reset, White, obj.Key, Reset)
		} else {
			fmt.Printf("    %s%s%s\n", White, obj.Key, Reset)
		}
	}
}

// ─────────────────────────────────────────────
//   gsutil IAM CHECK
// ─────────────────────────────────────────────

func gsutilIAM(bucket string, anon bool) CmdResult {
	method := "Authenticated"
	if anon {
		method = "Anonymous"
	}
	logInfo("%s IAM check: gs://%s", method, bucket)

	var cmd []string
	if anon {
		cmd = []string{"gsutil", "-o", "Credentials:gs_service_key_file=", "iam", "get", "gs://" + bucket}
	} else {
		cmd = []string{"gsutil", "iam", "get", "gs://" + bucket}
	}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 30*time.Second)
	result := CmdResult{Method: "iam_" + strings.ToLower(method)}

	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Raw = stdout
		logSuccess("%s IAM policy read SUCCESS", method)
		printGCPIAMPolicy(stdout)
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if strings.Contains(result.Error, "AccessDeniedException") || strings.Contains(result.Error, "403") {
			logWarn("%s IAM → ACCESS DENIED", method)
		} else if result.Error != "" {
			logWarn("%s IAM failed: %s", method, truncate(result.Error, 120))
		}
	}
	return result
}

func printGCPIAMPolicy(raw string) {
	if Silent {
		return
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return
	}
	bindings, ok := data["bindings"].([]interface{})
	if !ok {
		return
	}
	for _, b := range bindings {
		binding, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		role := fmt.Sprint(binding["role"])
		members, _ := binding["members"].([]interface{})
		for _, m := range members {
			member := fmt.Sprint(m)
			color := Gray
			if strings.Contains(member, "allUsers") || strings.Contains(member, "allAuthenticatedUsers") {
				color = Red
			}
			fmt.Printf("    %sROLE%s  %s%-40s%s  %s%s%s\n",
				Green, Reset, Cyan, role, Reset, color, member, Reset)
		}
	}
}

// ─────────────────────────────────────────────
//   GCP WRITE / DELETE TEST
// ─────────────────────────────────────────────

func gcpWriteTest(bucket string) WriteTestResult {
	result := WriteTestResult{}
	filename := fmt.Sprintf("secrets%06d.txt", rand.Intn(1000000))
	content := "XACKB was here\n" // base64: WEFDS0Igd2FzIGhlcmUK

	tmpPath := "/tmp/" + filename
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		logWarn("Could not create temp proof file: %v", err)
		return result
	}
	defer os.Remove(tmpPath)

	logInfo("Write test proof file: %s%s%s", Cyan, filename, Reset)

	gsURI := fmt.Sprintf("gs://%s/%s", bucket, filename)

	// Upload — Anonymous
	{
		cmd := []string{"gsutil", "-o", "Credentials:gs_service_key_file=", "cp", tmpPath, gsURI}
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.UploadAnon = true
			logResult("  UPLOAD (anon)", bucket, "WRITE", "gsutil cp succeeded without credentials!")
		} else if strings.Contains(stderr, "AccessDeniedException") || strings.Contains(stderr, "403") {
			logResult("  UPLOAD (anon)", bucket, "ACCESS_DENIED", "")
		} else {
			logResult("  UPLOAD (anon)", bucket, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	// Upload — Authenticated
	if !result.UploadAnon {
		cmd := []string{"gsutil", "cp", tmpPath, gsURI}
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.UploadAuth = true
			logResult("  UPLOAD (auth)", bucket, "WRITE", "gsutil cp succeeded with credentials!")
		} else if strings.Contains(stderr, "AccessDeniedException") || strings.Contains(stderr, "403") {
			logResult("  UPLOAD (auth)", bucket, "ACCESS_DENIED", "")
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
		cmd := []string{"gsutil", "ls", gsURI}
		if result.UploadAnon {
			cmd = []string{"gsutil", "-o", "Credentials:gs_service_key_file=", "ls", gsURI}
		}
		rc, stdout, _ := runCmd(cmd, 15*time.Second)
		if rc == 0 && strings.Contains(stdout, filename) {
			logSuccess("Upload verified: %s exists in bucket", filename)
		}
	}

	// Delete — Anonymous
	{
		cmd := []string{"gsutil", "-o", "Credentials:gs_service_key_file=", "rm", gsURI}
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.DeleteAnon = true
			logResult("  DELETE (anon)", bucket, "WRITE", "gsutil rm succeeded without credentials!")
		} else if strings.Contains(stderr, "AccessDeniedException") || strings.Contains(stderr, "403") {
			logResult("  DELETE (anon)", bucket, "ACCESS_DENIED", "")
		} else {
			logResult("  DELETE (anon)", bucket, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	// Delete — Authenticated
	if !result.DeleteAnon {
		cmd := []string{"gsutil", "rm", gsURI}
		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.DeleteAuth = true
			logResult("  DELETE (auth)", bucket, "WRITE", "gsutil rm succeeded with credentials!")
		} else if strings.Contains(stderr, "AccessDeniedException") || strings.Contains(stderr, "403") {
			logResult("  DELETE (auth)", bucket, "ACCESS_DENIED", "")
		} else {
			logResult("  DELETE (auth)", bucket, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	// Re-upload proof if deleted
	deleteSucceeded := result.DeleteAnon || result.DeleteAuth
	if deleteSucceeded {
		cmd := []string{"gsutil", "cp", tmpPath, gsURI}
		if result.UploadAnon {
			cmd = []string{"gsutil", "-o", "Credentials:gs_service_key_file=", "cp", tmpPath, gsURI}
		}
		runCmd(cmd, 30*time.Second) // silent re-upload
	}
	result.ProofFile = filename
	result.ProofLeft = true
	logSuccess("Proof of concept left: gs://%s/%s", bucket, filename)

	return result
}

// ─────────────────────────────────────────────
//   GCP FINDINGS
// ─────────────────────────────────────────────

func collectGCPFindings(r BucketResult) []string {
	var f []string
	if r.ListAnon.Accessible {
		f = append(f, fmt.Sprintf("PUBLIC LIST: Anonymous gsutil ls succeeded — %d objects", len(r.ListAnon.Objects)))
	}
	if r.ListAuth.Accessible {
		f = append(f, fmt.Sprintf("AUTHENTICATED LIST: Signed gsutil ls succeeded — %d objects", len(r.ListAuth.Objects)))
	}
	if r.ACLAnon.Accessible {
		f = append(f, "IAM POLICY (anonymous): Bucket IAM readable without credentials")
	}
	if r.ACLAuth.Accessible {
		f = append(f, "IAM POLICY (authenticated): Bucket IAM readable with your creds")
	}
	for _, p := range r.S3Scan.AllPerms {
		f = append(f, "S3SCANNER AllUsers: "+p)
	}
	for _, p := range r.S3Scan.AuthPerms {
		f = append(f, "S3SCANNER AuthUsers: "+p)
	}
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
