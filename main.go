package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
//   CONFIG
// ─────────────────────────────────────────────

type Config struct {
	Target       string
	Buckets      string
	BucketsGCP   string
	Permutations string
	Resolvers    string
	Output       string
	Clouds       string
	Workers      int
	SkipPerms    bool
	NoColor      bool
	OpenOnly     bool
}

// ─────────────────────────────────────────────
//   TOOL CHECK
// ─────────────────────────────────────────────

func checkTools() {
	logSection("Tool Availability Check")
	tools := []struct {
		name string
		hint string
	}{
		{"aws", "AWS CLI  (pip install awscli / https://aws.amazon.com/cli/)"},
		{"s3scanner", "S3Scanner (go install github.com/sa7mon/S3Scanner@latest)"},
		{"gsutil", "Google Cloud SDK  (apt install google-cloud-cli)"},
	}
	for _, t := range tools {
		if _, err := exec.LookPath(t.name); err == nil {
			logSuccess("%-15s found", t.name)
		} else {
			logWarn("%-15s NOT FOUND  →  %s", t.name, t.hint)
		}
	}
}

// ─────────────────────────────────────────────
//   ENTRYPOINT
// ─────────────────────────────────────────────

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Target, "t", "", "Target name for bucket discovery")
	flag.StringVar(&cfg.Buckets, "b", "", "Comma-separated AWS bucket name(s) to scan directly")
	flag.StringVar(&cfg.BucketsGCP, "bg", "", "Comma-separated GCS bucket name(s) to scan directly")
	flag.StringVar(&cfg.Permutations, "p", "permutations.txt", "Permutations wordlist file")
	flag.StringVar(&cfg.Resolvers, "r", "", "DNS resolvers file")
	flag.StringVar(&cfg.Output, "o", "", "Save JSON report to file")
	flag.StringVar(&cfg.Clouds, "clouds", "aws,gcp,azure,alibaba", "Comma-separated clouds to scan (aws,gcp,azure,alibaba)")
	flag.IntVar(&cfg.Workers, "w", 20, "Number of concurrent workers")
	flag.BoolVar(&cfg.SkipPerms, "skip-perms-check", false, "Try ACL enum even without READ_ACP")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI colors")
	flag.BoolVar(&cfg.OpenOnly, "open", false, "Only deep-scan OPEN buckets (skip PRIVATE)")

	// -s for silent mode
	silentFlag := flag.Bool("s", false, "Silent mode — only show final report")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `%sCloud-Could%s — Multi-Cloud Pentesting Framework by %sk3rn3lbr3ach3r%s

%sUsage:%s
  cloud-could -t TARGET [-p perms.txt] [-r resolvers.txt] [-clouds aws,gcp] [-o report.json]
  cloud-could -b bucket1,bucket2 [-o report.json]
  cloud-could -bg gcpbucket1,gcpbucket2 [-o report.json]

%sExamples:%s
  # Full multi-cloud scan (AWS + GCS + Azure + Alibaba):
  cloud-could -t name -p permutations.txt -r resolvers.txt

  # AWS-only scan:
  cloud-could -t name -p permutations.txt -clouds aws

  # GCS-only scan:
  cloud-could -t name -p permutations.txt -clouds gcp

  # Scan specific AWS buckets directly:
  cloud-could -b name1,name2,name3

  # Scan specific GCS buckets directly:
  cloud-could -bg my-gcs-bucket,test-storage

  # Silent mode — only final report:
  cloud-could -s -t name -p permutations.txt

  # Only deep-scan open buckets:
  cloud-could -open -t name -p permutations.txt

  # Save JSON report:
  cloud-could -t name -p permutations.txt -o results.json

%sFlags:%s
`, Bold, Reset, Cyan, Reset, Bold, Reset, Bold, Reset, Bold, Reset)
		flag.PrintDefaults()
	}

	flag.Parse()

	if cfg.NoColor {
		disableColors()
	}

	if *silentFlag {
		Silent = true
	}

	if cfg.Target == "" && cfg.Buckets == "" && cfg.BucketsGCP == "" {
		printBanner()
		flag.Usage()
		os.Exit(0)
	}

	printBanner()

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Printf("\n%s[!] Interrupted by user. Partial results may be available.%s\n", Yellow, Reset)
		os.Exit(1)
	}()

	checkTools()

	startTime := time.Now()

	// Determine which cloud endpoints to use
	clouds := strings.Split(cfg.Clouds, ",")
	endpoints := filterEndpoints(clouds)

	// ── Phase 1: Discover Buckets ──────────────
	var discovered []DiscoveredBucket

	if cfg.Target != "" {
		resolvers := loadResolvers(cfg.Resolvers)
		permutations := loadPermutations(cfg.Target, cfg.Permutations)
		logInfo("Generated %s%d%s permutations from target '%s%s%s'",
			Cyan, len(permutations), Reset, Cyan, cfg.Target, Reset)
		discovered = huntBuckets(permutations, resolvers, cfg.Workers, endpoints)
	}

	// Add manually specified AWS buckets
	if cfg.Buckets != "" {
		for _, b := range strings.Split(cfg.Buckets, ",") {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			found := false
			for _, d := range discovered {
				if d.Name == b && d.Cloud == "aws" {
					found = true
					break
				}
			}
			if !found {
				discovered = append(discovered, DiscoveredBucket{
					Name:     b,
					Hostname: b + ".s3.amazonaws.com",
					Cloud:    "aws",
					Service:  "AWS Bucket",
					State:    "MANUAL",
				})
			}
		}
	}

	// Add manually specified GCS buckets
	if cfg.BucketsGCP != "" {
		for _, b := range strings.Split(cfg.BucketsGCP, ",") {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			found := false
			for _, d := range discovered {
				if d.Name == b && d.Cloud == "gcp" {
					found = true
					break
				}
			}
			if !found {
				discovered = append(discovered, DiscoveredBucket{
					Name:     b,
					Hostname: b + ".storage.googleapis.com",
					Cloud:    "gcp",
					Service:  "GCS Bucket",
					State:    "MANUAL",
				})
			}
		}
	}

	if len(discovered) == 0 {
		logWarn("No buckets to scan. Exiting.")
		return
	}

	// ── Filter: -open flag ─────────────────────
	if cfg.OpenOnly {
		var filtered []DiscoveredBucket
		for _, b := range discovered {
			if b.State == "OPEN" || b.State == "MANUAL" || b.State == "UNKNOWN" {
				filtered = append(filtered, b)
			} else {
				logInfo("Skipping %s [%s] — state: %s (use without -open to include)", b.Name, b.Cloud, b.State)
			}
		}
		discovered = filtered
		if len(discovered) == 0 {
			logWarn("No OPEN buckets to scan after filtering. Exiting.")
			return
		}
	}

	// ── Phase 2+3: Deep Scan ───────────────────
	logSection(fmt.Sprintf("Starting Deep Scan — %d bucket(s)", len(discovered)))
	var results []BucketResult
	for _, bucket := range discovered {
		result := deepScan(bucket, cfg)
		results = append(results, result)
		printBucketSummary(result)
		time.Sleep(500 * time.Millisecond)
	}

	// ── Final Report ───────────────────────────
	elapsed := time.Since(startTime)
	printFinalReport(results, elapsed)

	if cfg.Output != "" {
		saveJSONReport(results, cfg.Output)
	}
}

// createFile creates a file (used by scan.go for JSON report)
func createFile(path string) (*os.File, error) {
	return os.Create(path)
}
