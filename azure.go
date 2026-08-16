package main

import (
	"encoding/json"
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
//   AZURE DEEP SCAN
// -----------------------------------------------

func azureDeepScan(bucket DiscoveredBucket, cfg Config) BucketResult {
	name := bucket.Name
	result := BucketResult{
		Bucket:    name,
		Cloud:     "azure",
		HuntState: bucket.State,
	}

	// Determine the Azure service type from the hostname
	service := detectAzureService(bucket.Hostname)

	if !Silent {
		fmt.Printf("\n%s%s%s%s\n", Bold, Magenta, strings.Repeat("=", 70), Reset)
		fmt.Printf("%s%s  TARGET AZURE %s: %s%s\n", Bold, Magenta, strings.ToUpper(service), name, Reset)
		fmt.Printf("%s%s%s%s\n", Bold, Magenta, strings.Repeat("=", 70), Reset)
	}

	switch service {
	case "blob":
		azureBlobDeepScan(&result, bucket, cfg)
	case "file":
		azureFileShareScan(&result, bucket)
	case "table":
		azureTableScan(&result, bucket)
	case "queue":
		azureQueueScan(&result, bucket)
	case "webapp":
		azureWebAppScan(&result, bucket)
	default:
		azureBlobDeepScan(&result, bucket, cfg)
	}

	result.Findings = collectAzureFindings(result, service)
	return result
}

func detectAzureService(hostname string) string {
	switch {
	case strings.Contains(hostname, "blob.core.windows.net"):
		return "blob"
	case strings.Contains(hostname, "file.core.windows.net"):
		return "file"
	case strings.Contains(hostname, "table.core.windows.net"):
		return "table"
	case strings.Contains(hostname, "queue.core.windows.net"):
		return "queue"
	case strings.Contains(hostname, "azurewebsites.net"):
		return "webapp"
	case strings.Contains(hostname, "azureedge.net"):
		return "cdn"
	default:
		return "blob"
	}
}

// -----------------------------------------------
//   AZURE BLOB STORAGE DEEP SCAN
// -----------------------------------------------

func azureBlobDeepScan(result *BucketResult, bucket DiscoveredBucket, cfg Config) {
	account := bucket.Name

	// Phase 2: Anonymous container enumeration via HTTP
	logSection(fmt.Sprintf("Phase 2 -- Azure Anonymous Enum [%s]", account))
	result.ListAnon = azureListContainersAnon(account)

	// Phase 3: Authenticated enumeration via az CLI
	logSection(fmt.Sprintf("Phase 3 -- Azure CLI Deep Enum [%s]", account))

	if !Silent {
		fmt.Printf("\n%s  -- Container Listing (Authenticated) -%s\n", Gray, Reset)
	}
	result.ListAuth = azureListContainersAuth(account)

	// ACL / Access Level Checks
	if !Silent {
		fmt.Printf("\n%s  -- Container Access Level Check -%s\n", Gray, Reset)
	}
	result.ACLAnon = azureCheckContainerAccess(account, result.ListAnon, result.ListAuth)

	// Storage Account Properties
	if !Silent {
		fmt.Printf("\n%s  -- Storage Account Properties -%s\n", Gray, Reset)
	}
	result.PolicyAuth = azureGetAccountProperties(account)

	// CORS Configuration
	if !Silent {
		fmt.Printf("\n%s  -- CORS Configuration -%s\n", Gray, Reset)
	}
	result.CORSCheck = azureGetCORS(account)

	// Soft Delete & Versioning
	if !Silent {
		fmt.Printf("\n%s  -- Soft Delete / Versioning -%s\n", Gray, Reset)
	}
	result.Versioning = azureCheckSoftDelete(account)

	// Static Website Hosting
	if !Silent {
		fmt.Printf("\n%s  -- Static Website Hosting -%s\n", Gray, Reset)
	}
	result.WebsiteCfg = azureCheckWebsite(account)

	// SAS Token / Public Access Block
	if !Silent {
		fmt.Printf("\n%s  -- Public Access Configuration -%s\n", Gray, Reset)
	}
	result.PubBlock = azureCheckPublicAccess(account)

	// Write/Delete Permission Test
	if !Silent {
		fmt.Printf("\n%s  -- Write / Delete Permission Test -%s\n", Gray, Reset)
	}
	result.WriteTest = azureWriteTest(account)
}

// -----------------------------------------------
//   ANONYMOUS CONTAINER ENUMERATION (HTTP)
// -----------------------------------------------

// Azure XML response types for anonymous enumeration
type azureEnumContainersResult struct {
	XMLName    xml.Name         `xml:"EnumerationResults"`
	Containers []azureContainer `xml:"Containers>Container"`
}

type azureContainer struct {
	Name       string `xml:"Name"`
	Properties struct {
		LastModified string `xml:"Last-Modified"`
		PublicAccess string `xml:"PublicAccess"`
	} `xml:"Properties"`
}

type azureBlobListResult struct {
	XMLName xml.Name    `xml:"EnumerationResults"`
	Blobs   []azureBlob `xml:"Blobs>Blob"`
}

type azureBlob struct {
	Name       string `xml:"Name"`
	Properties struct {
		LastModified  string `xml:"Last-Modified"`
		ContentLength string `xml:"Content-Length"`
		ContentType   string `xml:"Content-Type"`
	} `xml:"Properties"`
}

func azureListContainersAnon(account string) CmdResult {
	logInfo("Anonymous container enumeration: %s.blob.core.windows.net", account)
	result := CmdResult{Method: "anon"}

	// Try to list containers (usually fails unless account-level public access is enabled)
	listURL := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", account)
	logInfo("GET %s%s%s", Gray, listURL, Reset)

	client := getHTTPClient()
	resp, err := client.Get(listURL)
	if err != nil {
		result.Error = err.Error()
		logWarn("Container listing failed: %s", truncate(err.Error(), 80))
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		result.Accessible = true
		result.Raw = bodyStr
		logSuccess("ANONYMOUS container listing SUCCESS!")

		// Parse containers
		var enumResult azureEnumContainersResult
		if err := xml.Unmarshal(body, &enumResult); err == nil {
			for _, c := range enumResult.Containers {
				result.Objects = append(result.Objects, S3Object{
					Key:  c.Name,
					Date: c.Properties.LastModified,
					Size: c.Properties.PublicAccess,
				})
				access := c.Properties.PublicAccess
				if access == "" {
					access = "private"
				}
				logInfo("  Container: %s%s%s (access: %s%s%s)",
					Cyan, c.Name, Reset, Yellow, access, Reset)
			}
			logSuccess("Found %d container(s)", len(enumResult.Containers))
		}

		// Try listing blobs in each discovered container
		for _, c := range result.Objects {
			azureEnumBlobsAnon(account, c.Key)
		}
	} else if resp.StatusCode == 403 {
		result.Error = "AccessDenied"
		logWarn("Container listing -> ACCESS DENIED (expected for most accounts)")

		// Try well-known container names
		azureBruteContainers(account, &result)
	} else if resp.StatusCode == 404 {
		result.Error = "AccountNotFound"
		logWarn("Storage account not found (404)")
	} else {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		logWarn("Container listing returned HTTP %d", resp.StatusCode)

		// Still try common containers
		azureBruteContainers(account, &result)
	}

	return result
}

func azureBruteContainers(account string, result *CmdResult) {
	commonContainers := []string{
		"$web", "$logs", "$root", "data", "files", "images", "media",
		"backup", "backups", "uploads", "public", "private", "assets",
		"content", "documents", "downloads", "static", "www", "cdn",
		"logs", "archive", "temp", "test", "dev", "staging", "prod",
		"config", "secrets", "keys", "certificates", "vhds", "disks",
	}

	logInfo("Brute-forcing %d common container names...", len(commonContainers))
	client := getHTTPClient()
	foundCount := 0

	for _, container := range commonContainers {
		blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list",
			account, container)

		resp, err := client.Get(blobURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		switch resp.StatusCode {
		case 200:
			result.Objects = append(result.Objects, S3Object{Key: container, Size: "PUBLIC"})
			logResult("  Container", container, "OPEN", "publicly accessible!")
			foundCount++
		case 404:
			// Container doesn't exist
			continue
		case 403:
			result.Objects = append(result.Objects, S3Object{Key: container, Size: "PRIVATE"})
			logResult("  Container", container, "PRIVATE", "exists but access denied")
			foundCount++
		}
	}

	if foundCount > 0 {
		result.Accessible = true
		logSuccess("Discovered %d container(s) via brute-force", foundCount)
	}
}

func azureEnumBlobsAnon(account, container string) {
	blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list&maxresults=50",
		account, container)

	client := getHTTPClient()
	resp, err := client.Get(blobURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var blobList azureBlobListResult
	if err := xml.Unmarshal(body, &blobList); err != nil {
		return
	}

	if len(blobList.Blobs) > 0 {
		logSuccess("  Blobs in '%s': %d found", container, len(blobList.Blobs))
		for i, blob := range blobList.Blobs {
			if i >= 15 {
				logInfo("    ... and %d more blobs", len(blobList.Blobs)-15)
				break
			}
			if !Silent {
				fmt.Printf("    %s%s%s  %s%s%s  %s%s%s\n",
					Gray, blob.Properties.LastModified, Reset,
					Cyan, blob.Properties.ContentLength, Reset,
					White, blob.Name, Reset)
			}
		}
	}
}

// -----------------------------------------------
//   AUTHENTICATED ENUMERATION (az CLI)
// -----------------------------------------------

func azureListContainersAuth(account string) CmdResult {
	logInfo("Authenticated container listing: %s", account)
	result := CmdResult{Method: "auth"}

	cmd := []string{"az", "storage", "container", "list",
		"--account-name", account,
		"--auth-mode", "login",
		"--output", "json"}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 30*time.Second)

	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Raw = stdout

		var containers []map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &containers); err == nil {
			logSuccess("Authenticated listing: %d container(s)", len(containers))
			for _, c := range containers {
				name := fmt.Sprint(c["name"])
				access := "private"
				if props, ok := c["properties"].(map[string]interface{}); ok {
					if pa, ok := props["publicAccess"]; ok && pa != nil {
						access = fmt.Sprint(pa)
					}
				}
				result.Objects = append(result.Objects, S3Object{Key: name, Size: access})
				logInfo("  Container: %s%s%s (access: %s)", Cyan, name, Reset, access)
			}
		}
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if strings.Contains(result.Error, "az login") || strings.Contains(result.Error, "not logged in") {
			logWarn("Not logged in to Azure CLI (run: az login)")
		} else if strings.Contains(result.Error, "not found") {
			logWarn("Azure CLI not installed")
		} else if result.Error != "" {
			logWarn("Auth listing failed: %s", truncate(result.Error, 120))
		}
	}

	return result
}

// -----------------------------------------------
//   CONTAINER ACCESS LEVEL CHECKS
// -----------------------------------------------

func azureCheckContainerAccess(account string, listAnon, listAuth CmdResult) CmdResult {
	result := CmdResult{Method: "access_level"}

	// Combine containers from both anon and auth
	containers := make(map[string]bool)
	for _, obj := range listAnon.Objects {
		containers[obj.Key] = true
	}
	for _, obj := range listAuth.Objects {
		containers[obj.Key] = true
	}

	if len(containers) == 0 {
		logInfo("No containers to check access levels for")
		return result
	}

	details := []string{}
	for container := range containers {
		// Check blob-level public access
		testURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container",
			account, container)
		client := getHTTPClient()
		resp, err := client.Head(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		accessLevel := "private"
		if resp.StatusCode == 200 {
			accessLevel = resp.Header.Get("x-ms-blob-public-access")
			if accessLevel == "" {
				accessLevel = "container"
			}
		}

		details = append(details, fmt.Sprintf("%s=%s", container, accessLevel))
		if accessLevel != "private" && accessLevel != "" {
			logWarn("Container '%s' public access: %s%s%s", container, Red, accessLevel, Reset)
			result.Accessible = true
		} else {
			logInfo("Container '%s' access: private", container)
		}
	}

	result.Raw = strings.Join(details, "\n")
	return result
}

// -----------------------------------------------
//   STORAGE ACCOUNT PROPERTIES
// -----------------------------------------------

func azureGetAccountProperties(account string) CmdResult {
	logInfo("Checking storage account properties: %s", account)
	result := CmdResult{Method: "account_properties"}

	cmd := []string{"az", "storage", "account", "show",
		"--name", account,
		"--output", "json"}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 20*time.Second)

	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Raw = stdout

		var props map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &props); err == nil {
			// Check key properties
			if httpsOnly, ok := props["enableHttpsTrafficOnly"].(bool); ok {
				if !httpsOnly {
					logWarn("HTTPS-only traffic: DISABLED -- HTTP allowed!")
				} else {
					logInfo("HTTPS-only traffic: enabled")
				}
			}
			if kind, ok := props["kind"].(string); ok {
				logInfo("Storage kind: %s", kind)
			}
			if sku, ok := props["sku"].(map[string]interface{}); ok {
				logInfo("SKU: %s", sku["name"])
			}
			if networkRules, ok := props["networkRuleSet"].(map[string]interface{}); ok {
				defaultAction := fmt.Sprint(networkRules["defaultAction"])
				logInfo("Network default action: %s", defaultAction)
				if strings.ToLower(defaultAction) == "allow" {
					logWarn("Network rules: DEFAULT ALLOW -- no network restrictions!")
				}
			}
			if minTLS, ok := props["minimumTlsVersion"].(string); ok {
				logInfo("Minimum TLS version: %s", minTLS)
				if minTLS != "TLS1_2" {
					logWarn("Minimum TLS < 1.2: %s", minTLS)
				}
			}
		}
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if strings.Contains(result.Error, "not found") || strings.Contains(result.Error, "could not be found") {
			logWarn("Storage account not found or no access")
		} else if result.Error != "" {
			logWarn("Account properties check failed: %s", truncate(result.Error, 120))
		}
	}

	return result
}

// -----------------------------------------------
//   CORS CONFIGURATION
// -----------------------------------------------

func azureGetCORS(account string) CmdResult {
	logInfo("Checking CORS configuration: %s", account)
	result := CmdResult{Method: "cors"}

	cmd := []string{"az", "storage", "cors", "list",
		"--account-name", account,
		"--services", "b",
		"--output", "json"}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 20*time.Second)

	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Raw = stdout

		if strings.Contains(stdout, "*") {
			logWarn("CORS: wildcard (*) found -- potential misconfiguration!")
		} else if stdout == "[]" || strings.TrimSpace(stdout) == "[]" {
			logInfo("CORS: no rules configured")
		} else {
			logInfo("CORS: rules configured (review manually)")
		}
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if strings.Contains(result.Error, "AuthorizationFailure") || strings.Contains(result.Error, "403") {
			logWarn("CORS check -> ACCESS DENIED")
		} else if result.Error != "" {
			logWarn("CORS check failed: %s", truncate(result.Error, 120))
		}
	}

	return result
}

// -----------------------------------------------
//   SOFT DELETE & VERSIONING
// -----------------------------------------------

func azureCheckSoftDelete(account string) CmdResult {
	logInfo("Checking soft delete / versioning: %s", account)
	result := CmdResult{Method: "soft_delete"}

	cmd := []string{"az", "storage", "account", "blob-service-properties", "show",
		"--account-name", account,
		"--output", "json"}
	logInfo("CMD: %s%s%s", Gray, strings.Join(cmd, " "), Reset)

	rc, stdout, stderr := runCmd(cmd, 20*time.Second)

	if rc == 0 && strings.TrimSpace(stdout) != "" {
		result.Accessible = true
		result.Raw = stdout

		var props map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &props); err == nil {
			// Check container soft delete
			if deletePolicy, ok := props["containerDeleteRetentionPolicy"].(map[string]interface{}); ok {
				enabled := fmt.Sprint(deletePolicy["enabled"])
				days := fmt.Sprint(deletePolicy["days"])
				if enabled == "true" {
					logInfo("Container soft delete: ENABLED (%s days) -- deleted containers may be recoverable", days)
				} else {
					logWarn("Container soft delete: DISABLED")
				}
			}
			// Check blob soft delete
			if deletePolicy, ok := props["deleteRetentionPolicy"].(map[string]interface{}); ok {
				enabled := fmt.Sprint(deletePolicy["enabled"])
				days := fmt.Sprint(deletePolicy["days"])
				if enabled == "true" {
					logInfo("Blob soft delete: ENABLED (%s days)", days)
				} else {
					logWarn("Blob soft delete: DISABLED")
				}
			}
			// Check versioning
			if versioning, ok := props["isVersioningEnabled"].(bool); ok {
				if versioning {
					logInfo("Blob versioning: %sENABLED%s -- old versions may be recoverable", Green, Reset)
				} else {
					logInfo("Blob versioning: disabled")
				}
			}
		}
	} else {
		result.Error = strings.TrimSpace(stderr + stdout)
		if result.Error != "" {
			logWarn("Soft delete check failed: %s", truncate(result.Error, 120))
		}
	}

	return result
}

// -----------------------------------------------
//   STATIC WEBSITE HOSTING
// -----------------------------------------------

func azureCheckWebsite(account string) CmdResult {
	logInfo("Checking static website hosting: %s", account)
	result := CmdResult{Method: "website"}

	// Check via HTTP -- Azure static websites use $web container
	webURL := fmt.Sprintf("https://%s.z13.web.core.windows.net/", account)
	client := getHTTPClient()
	resp, err := client.Get(webURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 404 {
			// 404 means website is enabled but no index document
			if resp.StatusCode == 200 {
				result.Accessible = true
				logWarn("Static website hosting ENABLED and serving content!")
				logInfo("Website URL: %s", webURL)
			} else {
				logInfo("Static website endpoint exists but returns 404 (no index document)")
			}
		}
	}

	// Also check via az CLI
	cmd := []string{"az", "storage", "blob", "service-properties", "show",
		"--account-name", account,
		"--output", "json"}
	rc, stdout, _ := runCmd(cmd, 15*time.Second)
	if rc == 0 && strings.Contains(stdout, "staticWebsite") {
		result.Raw = stdout
		if strings.Contains(stdout, "\"enabled\": true") || strings.Contains(stdout, "\"enabled\":true") {
			result.Accessible = true
			logWarn("Static website hosting confirmed ENABLED via CLI")
		}
	}

	if !result.Accessible {
		logInfo("Static website hosting: not detected")
	}

	return result
}

// -----------------------------------------------
//   PUBLIC ACCESS CONFIGURATION
// -----------------------------------------------

func azureCheckPublicAccess(account string) CmdResult {
	logInfo("Checking public access configuration: %s", account)
	result := CmdResult{Method: "pub_access"}

	cmd := []string{"az", "storage", "account", "show",
		"--name", account,
		"--query", "allowBlobPublicAccess",
		"--output", "tsv"}

	rc, stdout, stderr := runCmd(cmd, 15*time.Second)

	if rc == 0 {
		result.Accessible = true
		value := strings.TrimSpace(stdout)
		result.Raw = value

		switch strings.ToLower(value) {
		case "true":
			logWarn("Blob public access: ALLOWED -- containers can be set to public!")
			result.Raw = "PublicAccessAllowed"
		case "false":
			logInfo("Blob public access: BLOCKED at account level (good)")
			result.Raw = "PublicAccessBlocked"
		default:
			logInfo("Blob public access: %s (default: allowed in older accounts)", value)
		}
	} else {
		result.Error = strings.TrimSpace(stderr)
		if result.Error != "" {
			logWarn("Public access check failed: %s", truncate(result.Error, 80))
		}
	}

	return result
}

// -----------------------------------------------
//   WRITE / DELETE PERMISSION TEST
// -----------------------------------------------

func azureWriteTest(account string) WriteTestResult {
	result := WriteTestResult{}
	filename := fmt.Sprintf("cloud-could-poc-%06d.txt", rand.Intn(1000000))
	content := "Cloud-Could PoC -- authorized security testing\n"

	tmpPath := "/tmp/" + filename
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		logWarn("Could not create temp proof file: %v", err)
		return result
	}
	defer os.Remove(tmpPath)

	logInfo("Write test proof file: %s%s%s", Cyan, filename, Reset)

	// Try to upload to common containers anonymously via HTTP PUT
	containers := []string{"$root", "public", "uploads", "data", "test"}
	client := getHTTPClient()

	for _, container := range containers {
		blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s",
			account, container, filename)

		fileData, _ := os.ReadFile(tmpPath)
		req, err := http.NewRequest("PUT", blobURL, strings.NewReader(string(fileData)))
		if err != nil {
			continue
		}
		req.Header.Set("x-ms-blob-type", "BlockBlob")
		req.Header.Set("Content-Type", "text/plain")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 201 || resp.StatusCode == 200 {
			result.UploadAnon = true
			result.ProofFile = fmt.Sprintf("%s/%s", container, filename)
			result.ProofLeft = true
			logResult("  UPLOAD (anon)", account, "WRITE",
				fmt.Sprintf("PUT to %s succeeded without credentials!", container))
			break
		}
	}

	// Try authenticated upload via az CLI
	if !result.UploadAnon {
		cmd := []string{"az", "storage", "blob", "upload",
			"--account-name", account,
			"--container-name", "test",
			"--name", filename,
			"--file", tmpPath,
			"--auth-mode", "login",
			"--overwrite"}

		rc, _, stderr := runCmd(cmd, 30*time.Second)
		if rc == 0 {
			result.UploadAuth = true
			result.ProofFile = "test/" + filename
			result.ProofLeft = true
			logResult("  UPLOAD (auth)", account, "WRITE", "az storage blob upload succeeded!")
		} else if strings.Contains(stderr, "AuthorizationFailure") || strings.Contains(stderr, "403") {
			logResult("  UPLOAD (auth)", account, "ACCESS_DENIED", "")
		} else if strings.Contains(stderr, "ContainerNotFound") {
			logResult("  UPLOAD (auth)", account, "NOT_FOUND", "test container doesn't exist")
		} else if strings.Contains(stderr, "not logged in") || strings.Contains(stderr, "az login") {
			logResult("  UPLOAD (auth)", account, "ERROR", "not logged in to Azure CLI")
		} else {
			logResult("  UPLOAD (auth)", account, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	if !result.UploadAnon && !result.UploadAuth {
		logInfo("Write test: no upload permission -- skipping delete test")
		return result
	}

	// Delete test
	if result.UploadAnon {
		// Try anonymous delete
		parts := strings.SplitN(result.ProofFile, "/", 2)
		if len(parts) == 2 {
			deleteURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s",
				account, parts[0], parts[1])
			req, _ := http.NewRequest("DELETE", deleteURL, nil)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 202 || resp.StatusCode == 200 {
					result.DeleteAnon = true
					logResult("  DELETE (anon)", account, "WRITE", "anonymous delete succeeded!")
				}
			}
		}
	}

	if result.UploadAuth && !result.DeleteAnon {
		cmd := []string{"az", "storage", "blob", "delete",
			"--account-name", account,
			"--container-name", "test",
			"--name", filename,
			"--auth-mode", "login"}

		rc, _, stderr := runCmd(cmd, 20*time.Second)
		if rc == 0 {
			result.DeleteAuth = true
			logResult("  DELETE (auth)", account, "WRITE", "authenticated delete succeeded!")
		} else if strings.Contains(stderr, "AuthorizationFailure") {
			logResult("  DELETE (auth)", account, "ACCESS_DENIED", "")
		} else {
			logResult("  DELETE (auth)", account, "ERROR", truncate(strings.TrimSpace(stderr), 60))
		}
	}

	if result.ProofLeft {
		logSuccess("Proof of concept uploaded to: %s/%s", account, result.ProofFile)
	}

	return result
}

// -----------------------------------------------
//   AZURE FILE / TABLE / QUEUE SCANS (BASIC)
// -----------------------------------------------

func azureFileShareScan(result *BucketResult, bucket DiscoveredBucket) {
	logSection(fmt.Sprintf("Azure File Share Scan [%s]", bucket.Name))
	logInfo("Checking file share access for: %s", bucket.Hostname)

	client := getHTTPClient()
	shareURL := fmt.Sprintf("https://%s?comp=list", bucket.Hostname)
	resp, err := client.Get(shareURL)
	if err != nil {
		logWarn("File share check failed: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.ListAnon = CmdResult{Method: "anon", Accessible: true}
		logResult("  File Shares", bucket.Name, "OPEN", "anonymous listing succeeded!")
	} else if resp.StatusCode == 403 {
		result.ListAnon = CmdResult{Method: "anon", Error: "AccessDenied"}
		logWarn("File share listing -> ACCESS DENIED")
	}
}

func azureTableScan(result *BucketResult, bucket DiscoveredBucket) {
	logSection(fmt.Sprintf("Azure Table Scan [%s]", bucket.Name))
	logInfo("Checking table access for: %s", bucket.Hostname)

	client := getHTTPClient()
	tableURL := fmt.Sprintf("https://%s/Tables", bucket.Hostname)
	resp, err := client.Get(tableURL)
	if err != nil {
		logWarn("Table check failed: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.ListAnon = CmdResult{Method: "anon", Accessible: true}
		logResult("  Tables", bucket.Name, "OPEN", "anonymous table listing succeeded!")
	} else if resp.StatusCode == 403 {
		logWarn("Table listing -> ACCESS DENIED")
	}
}

func azureQueueScan(result *BucketResult, bucket DiscoveredBucket) {
	logSection(fmt.Sprintf("Azure Queue Scan [%s]", bucket.Name))
	logInfo("Checking queue access for: %s", bucket.Hostname)

	client := getHTTPClient()
	queueURL := fmt.Sprintf("https://%s?comp=list", bucket.Hostname)
	resp, err := client.Get(queueURL)
	if err != nil {
		logWarn("Queue check failed: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.ListAnon = CmdResult{Method: "anon", Accessible: true}
		logResult("  Queues", bucket.Name, "OPEN", "anonymous queue listing succeeded!")
	} else if resp.StatusCode == 403 {
		logWarn("Queue listing -> ACCESS DENIED")
	}
}

func azureWebAppScan(result *BucketResult, bucket DiscoveredBucket) {
	logSection(fmt.Sprintf("Azure WebApp Scan [%s]", bucket.Name))
	logInfo("Checking webapp: %s", bucket.Hostname)

	client := &http.Client{
		Transport: getHTTPClient().Transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	webURL := fmt.Sprintf("https://%s/", bucket.Hostname)
	resp, err := client.Get(webURL)
	if err != nil {
		logWarn("WebApp check failed: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		result.ListAnon = CmdResult{Method: "anon", Accessible: true, Raw: bodyStr}
		logResult("  WebApp", bucket.Name, "OPEN", "webapp is live and accessible")

		// Check for common misconfigs
		if strings.Contains(bodyStr, "Error 404") || strings.Contains(bodyStr, "Hey, App Service developers!") {
			logInfo("Default Azure App Service page detected -- potential takeover vector")
		}
	} else if resp.StatusCode == 404 {
		logWarn("WebApp returns 404 -- may be available for subdomain takeover!")
		result.ListAnon = CmdResult{Method: "anon", Error: "404 - potential takeover"}
	}

	// Check common Azure paths
	sensitivePaths := []string{"/.env", "/.git/config", "/web.config", "/server-info", "/elmah.axd"}
	for _, path := range sensitivePaths {
		checkURL := fmt.Sprintf("https://%s%s", bucket.Hostname, path)
		resp, err := client.Get(checkURL)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			logWarn("Sensitive path accessible: %s%s%s (HTTP 200)", Red, path, Reset)
		}
	}
}

// -----------------------------------------------
//   AZURE FINDINGS COLLECTION
// -----------------------------------------------

func collectAzureFindings(r BucketResult, service string) []string {
	var f []string

	if r.ListAnon.Accessible {
		switch service {
		case "blob":
			f = append(f, fmt.Sprintf("PUBLIC ACCESS: Anonymous container/blob listing succeeded -- %d item(s) exposed",
				len(r.ListAnon.Objects)))
		case "webapp":
			f = append(f, "WEBAPP: Application is publicly accessible")
		default:
			f = append(f, fmt.Sprintf("PUBLIC ACCESS: Anonymous %s listing succeeded", service))
		}
	}
	if r.ListAuth.Accessible {
		f = append(f, fmt.Sprintf("AUTHENTICATED ACCESS: az CLI container listing succeeded -- %d container(s)",
			len(r.ListAuth.Objects)))
	}
	if r.ACLAnon.Accessible {
		f = append(f, "PUBLIC CONTAINERS: One or more containers have public access level set")
	}
	if r.PolicyAuth.Accessible {
		if strings.Contains(r.PolicyAuth.Raw, "\"enableHttpsTrafficOnly\": false") {
			f = append(f, "HTTPS NOT ENFORCED: HTTP traffic allowed to storage account")
		}
		if strings.Contains(r.PolicyAuth.Raw, "\"defaultAction\": \"Allow\"") {
			f = append(f, "NETWORK RULES: Default action is Allow -- no network restrictions")
		}
	}
	if r.CORSCheck.Accessible && strings.Contains(r.CORSCheck.Raw, "*") {
		f = append(f, "CORS: Wildcard origin (*) -- potential CORS misconfiguration")
	}
	if r.Versioning.Accessible {
		raw := r.Versioning.Raw
		if strings.Contains(raw, "\"enabled\": false") || strings.Contains(raw, "\"enabled\":false") {
			f = append(f, "SOFT DELETE: Disabled -- deleted data is not recoverable")
		}
	}
	if r.WebsiteCfg.Accessible {
		f = append(f, "WEBSITE: Static website hosting enabled -- potential attack vector")
	}
	if r.PubBlock.Accessible && r.PubBlock.Raw == "PublicAccessAllowed" {
		f = append(f, "PUBLIC ACCESS: Blob public access ALLOWED at account level")
	}

	// Write test findings
	w := r.WriteTest
	if w.UploadAnon {
		f = append(f, "WRITE (anonymous): Blob upload succeeded without credentials")
	}
	if w.UploadAuth {
		f = append(f, "WRITE (authenticated): Blob upload succeeded with your creds")
	}
	if w.DeleteAnon {
		f = append(f, "DELETE (anonymous): Blob deletion succeeded without credentials")
	}
	if w.DeleteAuth {
		f = append(f, "DELETE (authenticated): Blob deletion succeeded with your creds")
	}
	if w.ProofLeft {
		f = append(f, fmt.Sprintf("PROOF OF CONCEPT: %s left in storage as evidence", w.ProofFile))
	}

	return f
}
