package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------
//   CONFIG
// -----------------------------------------------

type Config struct {
	Target         string
	Buckets        string
	BucketsGCP     string
	BucketsAzure   string
	BucketsAlibaba string
	Permutations   string
	Resolvers      string
	Output         string
	OutputHTML     string
	OutputCSV      string
	OutputMD       string
	Clouds         string
	Workers        int
	SkipPerms      bool
	NoColor        bool
	OpenOnly       bool
	SetupMode      bool
	// Evasion
	ProxyAddr   string
	ProxyFile   string
	DelayStr    string
	Jitter      float64
	RotateUA    bool
	MaxRetries  int
	InsecureTLS bool
}

// -----------------------------------------------
//   ENTRYPOINT
// -----------------------------------------------

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Target, "t", "", "Target name for bucket discovery")
	flag.StringVar(&cfg.Buckets, "b", "", "Comma-separated AWS bucket name(s) to scan directly")
	flag.StringVar(&cfg.BucketsGCP, "bg", "", "Comma-separated GCS bucket name(s) to scan directly")
	flag.StringVar(
		&cfg.BucketsAzure,
		"ba",
		"",
		"Comma-separated Azure storage account(s) to scan directly",
	)
	flag.StringVar(
		&cfg.BucketsAlibaba,
		"bal",
		"",
		"Comma-separated Alibaba OSS bucket(s) to scan directly",
	)
	flag.StringVar(&cfg.Permutations, "p", "permutations.txt", "Permutations wordlist file")
	flag.StringVar(&cfg.Resolvers, "r", "", "DNS resolvers file")
	flag.StringVar(&cfg.Output, "o", "", "Save JSON report to file")
	flag.StringVar(&cfg.OutputHTML, "oH", "", "Save HTML report to file")
	flag.StringVar(&cfg.OutputCSV, "oC", "", "Save CSV report to file")
	flag.StringVar(&cfg.OutputMD, "oM", "", "Save Markdown report to file")
	flag.StringVar(
		&cfg.Clouds,
		"clouds",
		"aws,gcp,azure,alibaba",
		"Comma-separated clouds to scan (aws,gcp,azure,alibaba)",
	)
	flag.IntVar(&cfg.Workers, "w", 20, "Number of concurrent workers")
	flag.BoolVar(&cfg.SkipPerms, "skip-perms-check", false, "Try ACL enum even without READ_ACP")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI colors")
	flag.BoolVar(&cfg.OpenOnly, "open", false, "Only deep-scan OPEN buckets (skip PRIVATE)")
	flag.BoolVar(
		&cfg.SetupMode,
		"setup",
		false,
		"Run interactive auto-setup to install missing tools",
	)

	// Evasion flags
	flag.StringVar(
		&cfg.ProxyAddr,
		"proxy",
		"",
		"Proxy URL (http://host:port or socks5://host:port)",
	)
	flag.StringVar(&cfg.ProxyFile, "proxy-file", "", "File containing proxy list (one per line)")
	flag.StringVar(&cfg.DelayStr, "delay", "", "Delay between requests (e.g. 500ms, 1s)")
	flag.Float64Var(&cfg.Jitter, "jitter", 0.3, "Jitter factor for delay (0.0-1.0)")
	flag.BoolVar(&cfg.RotateUA, "ua-rotate", false, "Rotate User-Agent headers per request")
	flag.IntVar(&cfg.MaxRetries, "retries", 3, "Max retries on rate-limited/failed requests")
	flag.BoolVar(
		&cfg.InsecureTLS,
		"insecure-tls",
		false,
		"Skip TLS certificate verification (only for intercepting proxies)",
	)

	// Silent mode
	silentFlag := flag.Bool("s", false, "Silent mode -- only show final report")
	verboseFlag := flag.Bool("v", false, "Verbose output")
	debugFlag := flag.Bool("vv", false, "Debug output (very verbose)")

	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`%sCloud-Could v2.0%s -- Multi-Cloud Pentesting Framework by %sk3rn3lbr3ach3r%s

%sUsage:%s
  cloud-could -t TARGET [-p perms.txt] [-r resolvers.txt] [-clouds aws,gcp] [-o report.json]
  cloud-could -b bucket1,bucket2 [-o report.json]
  cloud-could -bg gcpbucket1,gcpbucket2 [-o report.json]
  cloud-could -ba azureaccount1,azureaccount2 [-o report.json]
  cloud-could -bal alibababucket1,alibababucket2 [-o report.json]

%sExamples:%s
  # Full multi-cloud scan (AWS + GCS + Azure + Alibaba):
  cloud-could -t name -p permutations.txt -r resolvers.txt

  # AWS-only scan:
  cloud-could -t name -p permutations.txt -clouds aws

  # Azure-only scan:
  cloud-could -t name -p permutations.txt -clouds azure

  # Alibaba-only scan:
  cloud-could -t name -p permutations.txt -clouds alibaba

  # Scan specific buckets directly:
  cloud-could -b awsbucket1,awsbucket2
  cloud-could -bg gcpbucket1
  cloud-could -ba azureaccount1,azureaccount2
  cloud-could -bal alibababucket1,alibababucket2

  # With proxy rotation and evasion:
  cloud-could -t name -proxy-file proxies.txt -ua-rotate -delay 500ms

  # Through a single proxy:
  cloud-could -t name -proxy socks5://127.0.0.1:9050

  # Multi-format report output:
  cloud-could -t name -o report.json -oH report.html -oM report.md

  # Silent + save all reports:
  cloud-could -s -t name -o results.json -oH results.html

  # Auto-install missing tools:
  cloud-could -setup

%sFlags:%s
`,
			Bold,
			Reset,
			Cyan,
			Reset,
			Bold,
			Reset,
			Bold,
			Reset,
			Bold,
			Reset,
		)
		flag.PrintDefaults()
	}

	flag.Parse()

	if cfg.NoColor {
		disableColors()
	}

	if *silentFlag {
		Silent = true
	}
	if *verboseFlag {
		Verbose = true
	}
	if *debugFlag {
		Debug = true
		Verbose = true
	}

	// Handle -setup mode
	if cfg.SetupMode {
		printBanner()
		runAutoSetup(true)
		return
	}

	// If no target specified, show usage
	if cfg.Target == "" && cfg.Buckets == "" && cfg.BucketsGCP == "" &&
		cfg.BucketsAzure == "" && cfg.BucketsAlibaba == "" {
		printBanner()
		flag.Usage()
		os.Exit(0)
	}

	printBanner()

	// First-run auto-setup check (non-interactive)
	if isFirstRun() {
		runAutoSetup(false)
	}

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Printf(
			"\n%s[!] Interrupted by user. Partial results may be available.%s\n",
			Yellow,
			Reset,
		)
		os.Exit(1)
	}()

	// Build evasion config
	evasionCfg := NewEvasionConfig()
	evasionCfg.RotateUA = cfg.RotateUA
	evasionCfg.Jitter = cfg.Jitter
	evasionCfg.MaxRetries = cfg.MaxRetries
	evasionCfg.Verbose = Verbose
	evasionCfg.InsecureTLS = cfg.InsecureTLS

	if cfg.DelayStr != "" {
		d, err := time.ParseDuration(cfg.DelayStr)
		if err != nil {
			logError("Invalid delay format '%s': %v (use e.g. 500ms, 1s, 2s)", cfg.DelayStr, err)
			os.Exit(1)
		}
		evasionCfg.Delay = d
	}

	// Load proxies
	if cfg.ProxyFile != "" {
		proxies, err := LoadProxies(cfg.ProxyFile)
		if err != nil {
			logError("Failed to load proxy file: %v", err)
			os.Exit(1)
		}
		evasionCfg.Proxies = proxies
	}
	if cfg.ProxyAddr != "" {
		evasionCfg.Proxies = append(evasionCfg.Proxies, cfg.ProxyAddr)
	}

	// Show evasion config if features enabled
	if len(evasionCfg.Proxies) > 0 || evasionCfg.RotateUA || evasionCfg.Delay > 0 {
		logEvasionConfig(evasionCfg)
		// Set proxy env for CLI tools
		SetProxyEnvForCLI(&evasionCfg)
	}

	// Shared evasion-aware HTTP client for deep-scan requests (Azure/Alibaba)
	// so -proxy/-ua-rotate/-delay/-insecure-tls apply uniformly across clouds.
	resolvers := loadResolvers(cfg.Resolvers)
	InitSharedClient(evasionCfg, resolvers)

	// Enhanced tool check based on selected clouds
	clouds := strings.Split(cfg.Clouds, ",")
	checkToolsEnhanced(clouds)

	// Identity/auth context -- which principal (if any) will authenticated
	// checks run as for each cloud. Attached to reports as scan context.
	authContexts := resolveAuthContexts(clouds)

	startTime := time.Now()

	// Determine which cloud endpoints to use
	endpoints := filterEndpoints(clouds)

	// -- Phase 1: Discover Buckets --
	var discovered []DiscoveredBucket

	if cfg.Target != "" {
		permutations := loadPermutations(cfg.Target, cfg.Permutations)
		logInfo("Generated %s%d%s permutations from target '%s%s%s'",
			Cyan, len(permutations), Reset, Cyan, cfg.Target, Reset)
		discovered = huntBuckets(permutations, resolvers, cfg.Workers, endpoints, evasionCfg)
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

	// Add manually specified Azure storage accounts
	if cfg.BucketsAzure != "" {
		for _, b := range strings.Split(cfg.BucketsAzure, ",") {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			found := false
			for _, d := range discovered {
				if d.Name == b && d.Cloud == "azure" {
					found = true
					break
				}
			}
			if !found {
				discovered = append(discovered, DiscoveredBucket{
					Name:     b,
					Hostname: b + ".blob.core.windows.net",
					Cloud:    "azure",
					Service:  "Azure Blob",
					State:    "MANUAL",
				})
			}
		}
	}

	// Add manually specified Alibaba OSS buckets
	if cfg.BucketsAlibaba != "" {
		for _, b := range strings.Split(cfg.BucketsAlibaba, ",") {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			found := false
			for _, d := range discovered {
				if d.Name == b && d.Cloud == "alibaba" {
					found = true
					break
				}
			}
			if !found {
				discovered = append(discovered, DiscoveredBucket{
					Name:     b,
					Hostname: b + ".oss-cn-hangzhou.aliyuncs.com",
					Cloud:    "alibaba",
					Service:  "Alibaba Bucket",
					State:    "MANUAL",
				})
			}
		}
	}

	if len(discovered) == 0 {
		logWarn("No buckets to scan. Exiting.")
		return
	}

	// -- Filter: -open flag --
	if cfg.OpenOnly {
		var filtered []DiscoveredBucket
		for _, b := range discovered {
			if b.State == "OPEN" || b.State == "MANUAL" || b.State == "UNKNOWN" {
				filtered = append(filtered, b)
			} else {
				logInfo(
					"Skipping %s [%s] -- state: %s (use without -open to include)",
					b.Name,
					b.Cloud,
					b.State,
				)
			}
		}
		discovered = filtered
		if len(discovered) == 0 {
			logWarn("No OPEN buckets to scan after filtering. Exiting.")
			return
		}
	}

	// -- Phase 2+3: Deep Scan --
	logSection(fmt.Sprintf("Starting Deep Scan -- %d bucket(s)", len(discovered)))
	results := runDeepScanPool(discovered, cfg, &evasionCfg)

	// -- Final Report --
	elapsed := time.Since(startTime)
	printFinalReport(results, elapsed)

	if cfg.Output != "" {
		saveJSONReport(results, authContexts, cfg.Output)
	}
	if cfg.OutputHTML != "" {
		saveHTMLReport(results, authContexts, cfg.OutputHTML, elapsed)
	}
	if cfg.OutputCSV != "" {
		saveCSVReport(results, cfg.OutputCSV)
	}
	if cfg.OutputMD != "" {
		saveMarkdownReport(results, authContexts, cfg.OutputMD, elapsed)
	}
}

// runDeepScanPool runs deepScan across a bounded worker pool sized by cfg.Workers.
//
// CLI-proxy rotation (RotateCLIProxy) mutates process-wide env vars, so it is
// not safe to interleave across concurrent goroutines -- when proxies are
// configured, deep-scan falls back to a single worker (same behavior as the
// old sequential loop) to keep proxy rotation correct per bucket.
func runDeepScanPool(discovered []DiscoveredBucket, cfg Config, evasionCfg *EvasionConfig) []BucketResult {
	workers := cfg.Workers
	if workers < 1 {
		workers = 1
	}
	if len(evasionCfg.Proxies) > 0 && workers > 1 {
		logWarn("Proxy rotation enabled -- forcing deep-scan to 1 worker for correct per-bucket proxy rotation")
		workers = 1
	}
	if workers > len(discovered) {
		workers = len(discovered)
	}

	type job struct {
		idx    int
		bucket DiscoveredBucket
	}

	jobs := make(chan job, len(discovered))
	for i, b := range discovered {
		jobs <- job{idx: i, bucket: b}
	}
	close(jobs)

	var mu sync.Mutex
	var wg sync.WaitGroup
	results := make([]BucketResult, 0, len(discovered))

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				logInfo(
					"Scanning %d/%d: %s%s%s [%s]",
					j.idx+1,
					len(discovered),
					Cyan,
					j.bucket.Name,
					Reset,
					strings.ToUpper(j.bucket.Cloud),
				)

				if len(evasionCfg.Proxies) > 0 {
					mu.Lock()
					RotateCLIProxy(evasionCfg)
					mu.Unlock()
				}

				result := deepScan(j.bucket, cfg)

				mu.Lock()
				results = append(results, result)
				mu.Unlock()

				printBucketSummary(result)
			}
		}()
	}
	wg.Wait()

	return results
}

// createFile creates a file (used by scan.go for JSON report)
func createFile(path string) (*os.File, error) {
	return os.Create(path)
}
