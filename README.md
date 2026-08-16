# Cloud-Could v2.0

**Multi-Cloud Red Team Pentesting Framework** by **k3rn3lbr3ach3r**

A Go-based multi-cloud pentesting framework for automated bucket/storage discovery, permission enumeration, deep scanning, and write testing across AWS S3, Google Cloud Storage, Azure Blob Storage, and Alibaba Cloud OSS -- with built-in rate limit bypass and evasion capabilities.

## What's New in v2.1

- **Identity/Auth Context Banner** -- before scanning, the tool resolves and prints which principal (if any) authenticated-mode checks will run as for each cloud: `aws sts get-caller-identity`, GCP Application Default Credentials, `az account show`, `aliyun sts GetCallerIdentity`. Attached to every report as `scan_context` so findings are traceable to a specific identity.
- **Cross-Account Grant Detection** -- flags the specific AWS misconfiguration where a bucket is readable/writable by *any* AWS account (not just the owner), distinct from a fully public grant: an ACL grant to the `AuthenticatedUsers` predefined group, or a bucket policy `Principal: "*"` statement with no restricting `Condition`. Same idea for GCP's `allAuthenticatedUsers` IAM member. Reported as CRITICAL severity. Azure and Alibaba have no direct equivalent in their storage ACL models (see Limitations below).
- **GCP: native Go SDK** -- GCS deep-scan no longer shells out to `gsutil` (which Google is deprecating). It now uses `cloud.google.com/go/storage` directly with Application Default Credentials, removing the CLI dependency for anything except optional login via `gcloud auth application-default login`.
- **Deep-scan now honors `-w`** -- Phase 2/3 (deep enumeration) previously ran strictly sequentially with a hardcoded 500ms sleep regardless of `-w`. It now runs across a bounded worker pool sized by `-w`, same as Phase 1 discovery. (Falls back to 1 worker automatically when `-proxy`/`-proxy-file` is set, since CLI-tool proxying rotates process-wide environment variables that aren't safe to interleave across goroutines.)
- **Report security fixes** -- the HTML report previously interpolated bucket/object names into the page without escaping (a malicious bucket owner could plant a stored-XSS payload an analyst would trigger by opening the report); it's now HTML-escaped. The CSV report now uses a real CSV writer and defuses spreadsheet formula injection (`=`, `+`, `-`, `@` leading characters).

## What's New in v2.0

- **Full Azure Deep Scan** -- container/blob enumeration, SAS detection, CORS, network ACLs, write tests
- **Full Alibaba OSS Deep Scan** -- object listing, ACL/policy reads, referer policy, CORS, write tests
- **Auto-Setup System** -- first-run dependency detection + interactive auto-installation
- **Rate Limit Bypass** -- proxy rotation, User-Agent rotation, request jitter, exponential backoff
- **Multi-Format Reports** -- JSON, HTML, CSV, Markdown output with severity classification
- **Enhanced UI** -- progress bars, live stats, severity badges, verbose/debug modes
- **200+ Permutations** -- expanded wordlist with cloud-specific naming patterns
- **Severity Classification** -- findings auto-classified as Critical/High/Medium/Low/Info

## Feature Matrix

| Feature | AWS S3 | GCS | Azure | Alibaba |
|---------|--------|-----|-------|---------|
| Discovery | Yes | Yes | Yes (6 services) | Yes (14 regions) |
| S3Scanner enum | Yes | Yes (`-provider gcp`) | -- | -- |
| List objects | Yes `aws s3 ls` | Yes `gsutil ls` | Yes (HTTP + `az`) | Yes (HTTP + `aliyun`) |
| ACL / IAM read | Yes `get-bucket-acl` | Yes `gsutil iam get` | Yes (access levels) | Yes (HTTP API) |
| Bucket/Container policy | Yes `get-bucket-policy` | -- | Yes (account props) | Yes (HTTP API) |
| Public access block | Yes | -- | Yes (account level) | Yes (referer policy) |
| Versioning check | Yes | -- | Yes (soft delete) | Yes (logging config) |
| CORS config | Yes | -- | Yes (`az storage cors`) | Yes (HTTP API) |
| Website hosting | Yes | -- | Yes ($web container) | Yes (HTTP API) |
| Write test (upload) | Yes | Yes | Yes (HTTP PUT + `az`) | Yes (HTTP PUT + `aliyun`) |
| Delete test (rm) | Yes | Yes | Yes (HTTP DELETE + `az`) | Yes (HTTP DELETE + `aliyun`) |
| PoC proof file | Yes | Yes | Yes | Yes |
| Container brute-force | -- | -- | Yes (30+ names) | -- |
| WebApp scanning | -- | -- | Yes (sensitive paths) | -- |
| Network ACL review | -- | -- | Yes | -- |
| Referer/hotlink check | -- | -- | -- | Yes |

## Setup

### Quick Start (Auto-Setup)

```bash
git clone https://github.com/k3rn3lbr3ach3r/Cloud-could.git
cd Cloud-could
go build -o cloud-could .
./cloud-could -setup    # interactive tool installer
```

### Manual Setup

#### 1. Build Cloud-Could

```bash
go build -o cloud-could .
```

#### 2. Install AWS CLI

```bash
pip install awscli
aws configure   # optional -- needed for authenticated scans
```

#### 3. Install S3Scanner

```bash
go install github.com/sa7mon/S3Scanner@latest
```

#### 4. GCP credentials (no gsutil required)

GCS deep-scan uses the native Go SDK directly, so no CLI tool is required. For authenticated checks, set up Application Default Credentials:

```bash
curl https://sdk.cloud.google.com | bash    # optional, only needed for the login step below
gcloud auth application-default login       # optional -- needed for authenticated scans
```

#### 5. Install Azure CLI

```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login   # optional -- needed for authenticated scans
```

#### 6. Install Alibaba Cloud CLI

```bash
# Linux
curl -fsSL https://aliyuncli.alicdn.com/aliyun-cli-linux-latest-amd64.tgz -o /tmp/aliyun-cli.tgz
tar -xzf /tmp/aliyun-cli.tgz -C /usr/local/bin/
aliyun configure   # optional
```

## Usage

```
cloud-could -t TARGET [options]
cloud-could -b bucket1,bucket2                    # direct AWS buckets
cloud-could -bg gcpbucket1,gcpbucket2              # direct GCS buckets
cloud-could -ba azureaccount1,azureaccount2        # direct Azure storage accounts
cloud-could -bal alibababucket1,alibababucket2     # direct Alibaba OSS buckets
cloud-could -setup                                 # auto-install missing tools
```

### Core Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | | Target name for bucket discovery |
| `-b` | | Comma-separated AWS bucket names |
| `-bg` | | Comma-separated GCS bucket names |
| `-ba` | | Comma-separated Azure storage accounts |
| `-bal` | | Comma-separated Alibaba OSS buckets |
| `-p` | `permutations.txt` | Permutations wordlist |
| `-r` | | DNS resolvers file |
| `-clouds` | `aws,gcp,azure,alibaba` | Which clouds to scan |
| `-w` | `20` | Worker count |
| `-s` | `false` | Silent -- only final report |
| `-open` | `false` | Only deep-scan OPEN buckets |
| `-no-color` | `false` | Disable ANSI colors |
| `-v` | `false` | Verbose output |
| `-vv` | `false` | Debug output (very verbose) |
| `-setup` | `false` | Interactive auto-setup |

### Output Flags

| Flag | Description |
|------|-------------|
| `-o report.json` | Save JSON report |
| `-oH report.html` | Save HTML report (dark-themed, severity-coded) |
| `-oC report.csv` | Save CSV report |
| `-oM report.md` | Save Markdown report |

### Evasion Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-proxy` | | Single proxy URL (http://, socks5://) |
| `-proxy-file` | | File with proxy list (one per line) |
| `-delay` | | Request delay (e.g. 500ms, 1s, 2s) |
| `-jitter` | `0.3` | Jitter factor for delay (0.0-1.0) |
| `-ua-rotate` | `false` | Rotate User-Agent per request |
| `-retries` | `3` | Max retries on rate-limited requests |
| `-insecure-tls` | `false` | Skip TLS certificate verification (only needed behind an intercepting proxy) |

### Examples

```bash
# Full multi-cloud scan
cloud-could -t company -p permutations.txt -r resolvers.txt

# AWS only
cloud-could -t company -p permutations.txt -clouds aws

# Azure only
cloud-could -t company -p permutations.txt -clouds azure

# Alibaba only
cloud-could -t company -p permutations.txt -clouds alibaba

# Specific buckets by provider
cloud-could -b bucket1,bucket2
cloud-could -bg gcpbucket1,gcpbucket2
cloud-could -ba storageaccount1,storageaccount2
cloud-could -bal ossbucket1,ossbucket2

# With evasion (proxy rotation + UA rotation + delay)
cloud-could -t company -proxy-file proxies.txt -ua-rotate -delay 1s

# Through Tor
cloud-could -t company -proxy socks5://127.0.0.1:9050 -delay 2s

# Multi-format report output
cloud-could -t company -o report.json -oH report.html -oM report.md -oC report.csv

# Silent mode with all reports
cloud-could -s -t company -o results.json -oH results.html

# Only scan open buckets
cloud-could -open -t company -p permutations.txt

# Verbose with debug info
cloud-could -vv -t company -p permutations.txt
```

## Proxy File Format

Create a file with one proxy per line:

```
http://proxy1.example.com:8080
http://user:pass@proxy2.example.com:3128
socks5://127.0.0.1:9050
https://proxy3.example.com:443
```

## Report Formats

### JSON Report (`-o`)
Machine-readable format with full scan details for all buckets.

### HTML Report (`-oH`)
Dark-themed visual report with severity-coded findings, stat cards, and cloud-specific badges. Ideal for executive summaries and client deliverables.

### CSV Report (`-oC`)
Spreadsheet-compatible format with columns: Bucket, Cloud, Region, State, Severity, Finding.

### Markdown Report (`-oM`)
Markdown-formatted report with summary table and detailed findings. Compatible with GitHub, GitLab, and most documentation platforms.

## Architecture

```
main.go       -- Entry point, flag parsing, orchestration, deep-scan worker pool
hunt.go       -- Multi-cloud bucket discovery (Phase 1)
scan.go       -- AWS deep scan, reporting, findings collection, cross-account grant detection
gcloud.go     -- GCP/GCS deep scan (native cloud.google.com/go/storage SDK + S3Scanner)
azure.go      -- Azure deep scan (HTTP API + az CLI)
alibaba.go    -- Alibaba OSS deep scan (HTTP API + aliyun CLI)
identity.go   -- Per-cloud identity/credential resolution (STS/ADC/account show)
evasion.go    -- Rate limit bypass: proxy rotation, UA rotation, backoff
setup.go      -- Auto-dependency detection and installation
ui.go         -- Terminal UI: colors, progress, severity, logging
```

## Limitations

- **Cross-account grant detection is AWS/GCP only.** AWS's `AuthenticatedUsers` ACL group and GCP's `allAuthenticatedUsers` IAM member both represent "any authenticated account on this platform, not just the owner." Azure Blob Storage and Alibaba OSS have no equivalent concept in their storage ACL models (Azure exposes only container-level Blob/Container public access; Alibaba OSS ACL is public-read/public-read-write/private) -- there is nothing analogous to detect there.
- **CLI-based deep-scan (AWS, Azure, Alibaba) has no built-in request pacing independent of `-delay`.** `-delay`/`-jitter` govern the shared HTTP client used for discovery and for Azure/Alibaba's direct HTTP calls; `aws`/`az`/`aliyun` CLI invocations are not proxied through that rate limiter. Use `-w 1` if you need strictly serialized, gentler CLI-tool pacing.
- **Proxy rotation (`-proxy`/`-proxy-file`) forces deep-scan to a single worker.** CLI-tool proxying works by rewriting process-wide `HTTP_PROXY`/`HTTPS_PROXY` env vars between calls, which isn't safe to interleave across concurrent goroutines -- this is automatic and logged when it happens.

## License

For authorized security testing only.
