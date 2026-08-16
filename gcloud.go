package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// ─────────────────────────────────────────────
//   GCP CLIENTS (native SDK, replaces gsutil)
// ─────────────────────────────────────────────
//
// gsutil is deprecated by Google in favor of the native Go SDK / `gcloud
// storage`. Two clients are built once and reused for every bucket:
//   - authClient uses Application Default Credentials (gcloud auth
//     application-default login, GOOGLE_APPLICATION_CREDENTIALS, or a
//     workload identity) -- nil if no ADC is available.
//   - anonClient makes fully unauthenticated requests, for testing
//     anonymous/public access exactly like the old `gsutil -o
//     Credentials:gs_service_key_file=` trick did.

var (
	gcpAuthClient  *storage.Client
	gcpAnonClient  *storage.Client
	gcpClientsOnce sync.Once
)

func gcpClients(ctx context.Context) (auth *storage.Client, anon *storage.Client) {
	gcpClientsOnce.Do(func() {
		if c, err := storage.NewClient(ctx); err == nil {
			gcpAuthClient = c
		} else {
			logDebug("GCP: no Application Default Credentials available (%v) -- authenticated checks will be skipped", err)
		}
		if c, err := storage.NewClient(ctx, option.WithoutAuthentication()); err == nil {
			gcpAnonClient = c
		} else {
			logWarn("GCP: failed to build anonymous storage client: %v", err)
		}
	})
	return gcpAuthClient, gcpAnonClient
}

// gcpErrInfo extracts an HTTP-style status code and message from a GCS SDK
// error, mirroring what the old gsutil stderr-substring checks looked for.
func gcpErrInfo(err error) (code int, msg string) {
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		return gerr.Code, gerr.Message
	}
	return 0, err.Error()
}

// ─────────────────────────────────────────────
//   GCP DEEP SCAN
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

	ctx := context.Background()
	authClient, anonClient := gcpClients(ctx)

	// Phase 2: S3Scanner with -provider gcp
	result.S3Scan = runS3ScannerGCP(name)

	// Phase 3: native SDK deep enum
	logSection(fmt.Sprintf("Phase 3 — GCS Deep Enum [%s]", name))

	// List objects — anonymous (unauthenticated)
	if !Silent {
		fmt.Printf("\n%s  ── Listing Objects (Anonymous) ─────────────────────────────────%s\n", Gray, Reset)
	}
	result.ListAnon = gcsList(ctx, anonClient, name, true)

	// List objects — authenticated
	if !Silent {
		fmt.Printf("\n%s  ── Listing Objects (Authenticated) ─────────────────────────────%s\n", Gray, Reset)
	}
	result.ListAuth = gcsList(ctx, authClient, name, false)

	// IAM Policy check
	if !Silent {
		fmt.Printf("\n%s  ── GCS IAM Policy ──────────────────────────────────────────────%s\n", Gray, Reset)
	}
	result.ACLAnon = gcsIAM(ctx, anonClient, name, true)
	result.ACLAuth = gcsIAM(ctx, authClient, name, false)

	// Write/Delete permission test
	if !Silent {
		fmt.Printf("\n%s  ── Write / Delete Permission Test ──────────────────────────────%s\n", Gray, Reset)
	}
	result.WriteTest = gcpWriteTest(ctx, authClient, anonClient, name)

	// Collect findings
	result.Findings = collectGCPFindings(result)
	result.Findings = append(result.Findings, checkGCPCrossAccountGrants(result)...)
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
//   GCS LIST (native SDK)
// ─────────────────────────────────────────────

func gcsList(ctx context.Context, client *storage.Client, bucket string, anon bool) CmdResult {
	method := "auth"
	label := "Authenticated"
	if anon {
		method = "anon"
		label = "Anonymous"
	}
	result := CmdResult{Method: method}

	if client == nil {
		result.Error = "no credentials available"
		return result
	}

	logInfo("Trying %s list: gs://%s", label, bucket)

	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	it := client.Bucket(bucket).Objects(cctx, nil)
	var objects []S3Object
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			code, msg := gcpErrInfo(err)
			result.Error = msg
			switch code {
			case 403:
				logWarn("%s list → ACCESS DENIED", label)
			case 404:
				logWarn("Bucket does not exist (404)")
			default:
				if msg != "" {
					logWarn("%s list failed: %s", label, truncate(msg, 120))
				}
			}
			// Objects gathered before the error still count as a partial
			// success if any were returned.
			break
		}
		objects = append(objects, S3Object{
			Key:  attrs.Name,
			Size: strconv.FormatInt(attrs.Size, 10),
			Date: attrs.Updated.Format("2006-01-02"),
			Time: attrs.Updated.Format("15:04:05"),
		})
	}

	if len(objects) > 0 || result.Error == "" {
		result.Accessible = true
		result.Objects = objects
		logSuccess("%s LIST SUCCESS — %d object(s)", strings.ToUpper(label), len(objects))
		printGsutilObjectList(objects, 20)
	}
	return result
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
//   GCS IAM CHECK (native SDK)
// ─────────────────────────────────────────────

type gcpIAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

func gcsIAM(ctx context.Context, client *storage.Client, bucket string, anon bool) CmdResult {
	method := "Authenticated"
	if anon {
		method = "Anonymous"
	}
	result := CmdResult{Method: "iam_" + strings.ToLower(method)}

	if client == nil {
		result.Error = "no credentials available"
		return result
	}

	logInfo("%s IAM check: gs://%s", method, bucket)

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	policy, err := client.Bucket(bucket).IAM().V3().Policy(cctx)
	if err != nil {
		code, msg := gcpErrInfo(err)
		result.Error = msg
		switch code {
		case 403:
			logWarn("%s IAM → ACCESS DENIED", method)
		default:
			if msg != "" {
				logWarn("%s IAM failed: %s", method, truncate(msg, 120))
			}
		}
		return result
	}

	var bindings []gcpIAMBinding
	for _, b := range policy.Bindings {
		bindings = append(bindings, gcpIAMBinding{Role: b.Role, Members: b.Members})
	}
	raw, _ := json.Marshal(bindings)

	result.Accessible = true
	result.Raw = string(raw)
	logSuccess("%s IAM policy read SUCCESS", method)
	printGCPIAMPolicy(bindings)
	return result
}

func printGCPIAMPolicy(bindings []gcpIAMBinding) {
	if Silent {
		return
	}
	for _, b := range bindings {
		for _, member := range b.Members {
			color := Gray
			if strings.Contains(member, "allUsers") || strings.Contains(member, "allAuthenticatedUsers") {
				color = Red
			}
			fmt.Printf("    %sROLE%s  %s%-40s%s  %s%s%s\n",
				Green, Reset, Cyan, b.Role, Reset, color, member, Reset)
		}
	}
}

// checkGCPCrossAccountGrants flags the GCS analog of AWS's AuthenticatedUsers
// grant: a binding to the special member "allAuthenticatedUsers", which
// hands access to ANY Google account or service account, not just the
// bucket owner -- distinct from "allUsers" (fully public, already flagged
// via the S3Scanner AllUsers findings).
func checkGCPCrossAccountGrants(r BucketResult) []string {
	var f []string
	for _, acl := range []struct {
		res    CmdResult
		method string
	}{{r.ACLAnon, "anonymous"}, {r.ACLAuth, "authenticated"}} {
		if !acl.res.Accessible || acl.res.Raw == "" {
			continue
		}
		var bindings []gcpIAMBinding
		if err := json.Unmarshal([]byte(acl.res.Raw), &bindings); err != nil {
			continue
		}
		for _, b := range bindings {
			for _, member := range b.Members {
				if member == "allAuthenticatedUsers" {
					f = append(f, fmt.Sprintf(
						"CRITICAL: IAM binding (%s check) grants role %s to allAuthenticatedUsers — ANY Google account, not just the owner, has this access",
						acl.method, b.Role))
				}
			}
		}
	}
	return f
}

// ─────────────────────────────────────────────
//   GCP WRITE / DELETE TEST (native SDK)
// ─────────────────────────────────────────────

func gcpWriteTest(ctx context.Context, authClient, anonClient *storage.Client, bucket string) WriteTestResult {
	result := WriteTestResult{}
	filename := fmt.Sprintf("secrets%06d.txt", rand.Intn(1000000))
	content := []byte("XACKB was here\n")

	logInfo("Write test proof file: %s%s%s", Cyan, filename, Reset)

	upload := func(client *storage.Client) (ok bool, errMsg string) {
		if client == nil {
			return false, "no credentials available"
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		w := client.Bucket(bucket).Object(filename).NewWriter(cctx)
		if _, err := w.Write(content); err != nil {
			return false, err.Error()
		}
		if err := w.Close(); err != nil {
			_, msg := gcpErrInfo(err)
			return false, msg
		}
		return true, ""
	}

	// Upload — Anonymous
	if ok, errMsg := upload(anonClient); ok {
		result.UploadAnon = true
		logResult("  UPLOAD (anon)", bucket, "WRITE", "GCS write succeeded without credentials!")
	} else if errMsg != "" {
		logResult("  UPLOAD (anon)", bucket, classifyGCPWriteErr(errMsg), truncate(errMsg, 60))
	}

	// Upload — Authenticated
	if !result.UploadAnon {
		if ok, errMsg := upload(authClient); ok {
			result.UploadAuth = true
			logResult("  UPLOAD (auth)", bucket, "WRITE", "GCS write succeeded with credentials!")
		} else if errMsg != "" {
			logResult("  UPLOAD (auth)", bucket, classifyGCPWriteErr(errMsg), truncate(errMsg, 60))
		}
	}

	writeSucceeded := result.UploadAnon || result.UploadAuth
	if !writeSucceeded {
		logInfo("Write test: no upload permission — skipping delete test")
		return result
	}

	uploadClient := authClient
	if result.UploadAnon {
		uploadClient = anonClient
	}

	// Verify upload
	{
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if uploadClient != nil {
			if attrs, err := uploadClient.Bucket(bucket).Object(filename).Attrs(cctx); err == nil && attrs.Name == filename {
				logSuccess("Upload verified: %s exists in bucket", filename)
			}
		}
		cancel()
	}

	del := func(client *storage.Client) (ok bool, errMsg string) {
		if client == nil {
			return false, "no credentials available"
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := client.Bucket(bucket).Object(filename).Delete(cctx); err != nil {
			_, msg := gcpErrInfo(err)
			return false, msg
		}
		return true, ""
	}

	// Delete — Anonymous
	if ok, errMsg := del(anonClient); ok {
		result.DeleteAnon = true
		logResult("  DELETE (anon)", bucket, "WRITE", "GCS delete succeeded without credentials!")
	} else if errMsg != "" {
		logResult("  DELETE (anon)", bucket, classifyGCPWriteErr(errMsg), truncate(errMsg, 60))
	}

	// Delete — Authenticated
	if !result.DeleteAnon {
		if ok, errMsg := del(authClient); ok {
			result.DeleteAuth = true
			logResult("  DELETE (auth)", bucket, "WRITE", "GCS delete succeeded with credentials!")
		} else if errMsg != "" {
			logResult("  DELETE (auth)", bucket, classifyGCPWriteErr(errMsg), truncate(errMsg, 60))
		}
	}

	// Re-upload proof if deleted
	deleteSucceeded := result.DeleteAnon || result.DeleteAuth
	if deleteSucceeded {
		reuploadClient := authClient
		if result.UploadAnon {
			reuploadClient = anonClient
		}
		upload(reuploadClient) // silent re-upload
	}
	result.ProofFile = filename
	result.ProofLeft = true
	logSuccess("Proof of concept left: gs://%s/%s", bucket, filename)

	return result
}

func classifyGCPWriteErr(errMsg string) string {
	lower := strings.ToLower(errMsg)
	if strings.Contains(lower, "403") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "credentials") {
		return "ACCESS_DENIED"
	}
	return "ERROR"
}

// ─────────────────────────────────────────────
//   GCP FINDINGS
// ─────────────────────────────────────────────

func collectGCPFindings(r BucketResult) []string {
	var f []string
	if r.ListAnon.Accessible {
		f = append(f, fmt.Sprintf("PUBLIC LIST: Anonymous list succeeded — %d objects", len(r.ListAnon.Objects)))
	}
	if r.ListAuth.Accessible {
		f = append(f, fmt.Sprintf("AUTHENTICATED LIST: Signed list succeeded — %d objects", len(r.ListAuth.Objects)))
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
