# Cloud-Could v1.0

**Multi-Cloud Pentesting Framework** by **k3rn3lbr3ach3r**

A Go based cloud pentesting tool for automated bucket discovery, permission enumeration, and write testing across AWS S3, Google Cloud Storage, Azure, and Alibaba Cloud.

## Features

| Feature | AWS S3 | GCS | Azure | Alibaba |
|---------|--------|-----|-------|---------|
| Discovery | ✅ | ✅ | ✅ | ✅ (14 regions) |
| S3Scanner enum | ✅ | ✅ (`-provider gcp`) | ❌ | ❌ |
| List objects | ✅ `aws s3 ls` | ✅ `gsutil ls` | — | — |
| ACL / IAM read | ✅ `get-bucket-acl` | ✅ `gsutil iam get` | — | — |
| Bucket policy | ✅ `get-bucket-policy` | — | — | — |
| Public access block | ✅ | — | — | — |
| Versioning check | ✅ | — | — | — |
| CORS config | ✅ | — | — | — |
| Website hosting | ✅ | — | — | — |
| Write test (cp) | ✅ | ✅ | — | — |
| Delete test (rm) | ✅ | ✅ | — | — |
| PoC proof file | ✅ | ✅ | — | — |

## Setup

### 1. Build Cloud-Could

```bash
git clone <repo>
cd Cloud-could
go build -o cloud-could .
```

### 2. Install AWS CLI

```bash
pip install awscli
aws configure   # optional — needed for authenticated scans
```

### 3. Install S3Scanner

```bash
go install github.com/sa7mon/S3Scanner@latest
```

### 4. Install Google Cloud SDK (gsutil)

```bash
sudo apt-get update
sudo apt-get install apt-transport-https ca-certificates gnupg curl
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg

echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
sudo apt-get update && sudo apt-get install google-cloud-cli
```

Optional authentication:
```bash
gcloud auth login
```

## Usage

```
cloud-could -t TARGET [-p perms.txt] [-r resolvers.txt] [-clouds aws,gcp] [-o report.json]
cloud-could -b bucket1,bucket2                   # direct AWS buckets
cloud-could -bg gcpbucket1,gcpbucket2             # direct GCS buckets
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | | Target name for bucket discovery |
| `-b` | | Comma-separated AWS bucket names |
| `-bg` | | Comma-separated GCS bucket names |
| `-p` | `permutations.txt` | Permutations wordlist |
| `-r` | | DNS resolvers file |
| `-o` | | JSON report output |
| `-clouds` | `aws,gcp,azure,alibaba` | Which clouds to scan |
| `-w` | `20` | Worker count |
| `-s` | `false` | Silent — only final report |
| `-open` | `false` | Only deep-scan OPEN buckets |
| `-no-color` | `false` | Disable ANSI colors |

### Examples

```bash
# Full multi-cloud scan
cloud-could -t name -p permutations.txt -r resolvers.txt

# AWS only
cloud-could -t name -p permutations.txt -clouds aws

# GCS only
cloud-could -t name -p permutations.txt -clouds gcp

# Specific buckets
cloud-could -b bucket1,bucket2
cloud-could -bg gcpbucket1,gcpbucket2

# Silent — only show results
cloud-could -s -t name -p permutations.txt -o results.json

# Only scan open buckets (skip private)
cloud-could -open -t name -p permutations.txt
```



## License

For authorized security testing only.
