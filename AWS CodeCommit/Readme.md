# AWS CodeCommit Automated Security Scanning Pipeline

## Overview

This is a fully automated security scanning pipeline for AWS CodeCommit. Run one command (`python main.py`) and it scans every repository in your AWS account's CodeCommit service — no manual setup required per repo.

The flow is: discover all repos → commit `buildspec.yml` into each repo → create a CodeBuild project → run the build → download the 3 scan reports (Grype, Semgrep, Cisco AIBOM) locally.

---

## Prerequisites

Before running the script you need four things:

1. A `.env` file with your credentials (see below)
2. An IAM user with the right permissions
3. A Groq API key
4. At least one CodeCommit repository

---

## Step 1 — Create the `.env` File

Create a file named `.env` inside the `AWS CodeCommit/` folder with the following content:

```
AWS_DEFAULT_REGION=eu-north-1
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_HERE
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY_HERE
GROQ_API_KEY=YOUR_GROQ_KEY_HERE
```

Optional overrides (defaults shown):

```
AWS_S3_BUCKET=cytex-security-scan-reports
CODEBUILD_ROLE_NAME=cytex-codebuild-role
```

| Variable | Default | Purpose |
|---|---|---|
| `AWS_DEFAULT_REGION` | `us-east-1` | Region where your CodeCommit repos live |
| `AWS_ACCESS_KEY_ID` | — | AWS IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | — | AWS IAM user secret key |
| `GROQ_API_KEY` | — | Groq API key used by Cisco AIBOM for AI analysis |
| `AWS_S3_BUCKET` | `cytex-security-scan-reports` | S3 bucket for storing scan reports (created automatically) |
| `CODEBUILD_ROLE_NAME` | `cytex-codebuild-role` | IAM role auto-created for CodeBuild |

**`AWS_DEFAULT_REGION`** — the region shown in the top-right corner of the AWS Console (e.g. `us-east-1`, `eu-north-1`). Must be the same region where your CodeCommit repos are.

---

## Step 2 — Get `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

### Option A (Recommended) — Create a New IAM User

**2a. Create the user:**

1. Open **AWS Console → IAM → Users**
2. Click **Create user**
3. Enter a username (e.g. `codecommit-user`)
4. Click **Next**
5. On the permissions page, select **Attach policies directly**
6. Click **Next** → **Create user**

**2b. Attach permissions to the user:**

Go to **IAM → Users → `codecommit-user` → Permissions tab → Add permissions → Attach policies directly**

Search for and check each of the following managed policies:

| Policy | Why it's needed |
|---|---|
| `AmazonS3FullAccess` | Create the report bucket, enable versioning, upload/download scan results |
| `AWSCodeBuildAdminAccess` | Create and update CodeBuild projects, poll build status |
| `AWSCodePipeline_FullAccess` | Create pipelines, start executions, poll pipeline and action status |
| `IAMFullAccess` | Auto-create `cytex-codebuild-role` and `cytex-codepipeline-role` service roles |
| `CloudWatchLogsFullAccess` | CodeBuild log group creation |
| `AWSCodeCommitFullAccess` | List repos, read files, commit `buildspec.yml` |

Click **Next** → **Add permissions**

**2c. Generate the access key:**

Go to **IAM → Users → `codecommit-user` → Security credentials tab → Create access key**

- Use case: select **Application running outside AWS**
- Click through to **Create access key**
- Copy `Access key ID` → paste as `AWS_ACCESS_KEY_ID` in `.env`
- Copy `Secret access key` → paste as `AWS_SECRET_ACCESS_KEY` in `.env`

> You only see the secret key once. Copy it immediately.

### Option B — Use an Existing User

If you already have a user, go to **IAM → Users → your user → Permissions tab** and attach the same five policies listed above. Then go to **Security credentials → Create access key** to generate the key pair.

---

## Step 3 — Get `GROQ_API_KEY`

1. Sign up or log in at [https://console.groq.com](https://console.groq.com)
2. Go to **API Keys → Create API Key**
3. Copy the key and paste it as `GROQ_API_KEY` in `.env`

This key is required by Cisco AIBOM to perform AI-assisted analysis using the `llama-3.3-70b-versatile` model. Without it the script will exit immediately with a clear error.

---

## Step 4 — Create a CodeCommit Repository

You need at least one repository before running the script.

**Via AWS Console:**

1. Go to **AWS Console → CodeCommit → Repositories → Create repository**
2. Repository name: anything (e.g. `test-repo`)
3. Leave everything else as default → click **Create**

The repo can be empty — the script handles that by creating the first commit when it pushes `buildspec.yml`.

If you want the scanners to find more results, add some Python files with a `requirements.txt` before running.

**Via AWS CLI:**
```bash
aws codecommit create-repository --repository-name test-repo --region eu-north-1
```

---

## What Gets Created Automatically on First Run

The script creates two AWS resources automatically — both are reused on subsequent runs, never recreated:

| Resource | Name | What it is |
|---|---|---|
| **S3 bucket** | `cytex-security-scan-reports` | Stores the raw JSON scan reports uploaded by CodeBuild during each build |
| **IAM role** | `cytex-codebuild-role` | Service role that gives CodeBuild permission to read from CodeCommit, write to S3, and publish logs to CloudWatch |

The IAM role gets three managed policies attached automatically:
- `AWSCodeCommitReadOnly` — lets CodeBuild check out the repo
- `AmazonS3FullAccess` — lets CodeBuild upload the 3 report files to S3
- `CloudWatchLogsFullAccess` — lets CodeBuild write build logs

---

## Running the Pipeline

Install dependencies (from the project root):
```bash
pip install -r requirements.txt
```

Then:
```bash
cd "AWS CodeCommit"
python main.py
```

Expected output:
```
Region : eu-north-1
Bucket : cytex-security-scan-reports
  Created S3 bucket: cytex-security-scan-reports
  Created IAM role: cytex-codebuild-role (waiting 10s for propagation)
  IAM role ARN : arn:aws:iam::123456789012:role/cytex-codebuild-role

Found 1 repo(s) in CodeCommit (eu-north-1)

    Repo: test-repo
    Buildspec pushed to main
    CodeBuild project ready: cytex-scan-test-repo
    Build queued: cytex-scan-test-repo:a1b2c3d4-5678-...
    [0s] build cytex-scan-test-repo:a1b2c3d4-... -> IN_PROGRESS
    [15s] build cytex-scan-test-repo:a1b2c3d4-... -> IN_PROGRESS
    ...
    Build completed: SUCCEEDED
    AIBOM   : reports/aibom_aws_eu-north-1_test-repo_20260619120000.json
    SBOM    : sbom_reports/grype_aws_eu-north-1_test-repo_20260619120001.json
    Semgrep : sbom_reports/semgrep_aws_eu-north-1_test-repo_20260619120002.json
```

---

## How It Works — Step by Step

### Step 1 — One-Time Setup

**Ensure S3 bucket exists:**

Calls `s3.head_bucket()`. If the bucket does not exist (404), creates it in your configured region. If it exists and belongs to another AWS account (403), raises an error with instructions to rename via `.env`.

**Ensure IAM role exists:**

Calls `iam.get_role()`. If the role does not exist, creates it with the CodeBuild trust policy, attaches the three managed policies, then waits 10 seconds for IAM propagation. On subsequent runs it finds the existing role and returns its ARN immediately.

### Step 2 — Discover All Repos

Calls `get_repos()` using the CodeCommit paginator:

```
codecommit.list_repositories(sortBy="repositoryName", order="ascending")
```

Returns every repository in the account for the configured region. Pagination is handled automatically — there is no limit on number of repos.

### Step 3 — Per Repo: Push the Buildspec

Calls `push_buildspec()`. Internally it:

1. Reads the current `buildspec.yml` via `codecommit.get_file()`. If the file already exists and the content is identical, **skips the commit entirely**.
2. Gets the current HEAD commit ID via `codecommit.get_branch()` — required as `parentCommitId`.
3. For a **brand-new empty repo** (no commits yet), skips the parent commit ID — this creates the first commit on the branch.
4. Calls `codecommit.put_file()` with the YAML encoded as bytes.

The committed `buildspec.yml` defines a 3-phase build:

| Phase | Tool | What It Scans | Output |
|---|---|---|---|
| `build` | **Grype** | Known CVEs in dependencies | `grype-report.json` |
| `build` | **Semgrep** | Code vulnerabilities / bad patterns | `semgrep-report.json` |
| `build` | **Cisco AIBOM** | AI/ML components in the codebase | `aibom-report.cdx.json` |
| `post_build` | `aws s3 cp` | Uploads all 3 reports to S3 | `s3://{bucket}/{build_id}/{report}` |

The S3 upload path uses `$CODEBUILD_BUILD_ID` (automatically set by CodeBuild) transformed via `tr ':' '/'`. For example, build ID `cytex-scan-myrepo:abc-123` becomes S3 prefix `cytex-scan-myrepo/abc-123/`.

### Step 4 — Create the CodeBuild Project

Checks if `cytex-scan-{repo_name}` already exists via `codebuild.batch_get_projects()`. If not, creates it pointing at the CodeCommit repo. The project is configured with:

- **Image**: `aws/codebuild/standard:7.0` (Ubuntu 22.04, Python 3.11)
- **Compute**: `BUILD_GENERAL1_MEDIUM` (3 GB RAM, 2 vCPUs)
- **Environment variables**: `GROQ_API_KEY` and `BUCKET_NAME` (available inside the build)
- **Logs**: CloudWatch Logs under `/aws/codebuild/cytex-scan/{repo_name}`
- **Timeout**: 30 minutes

### Step 5 — Start and Poll the Build

Triggers an immediate build via `codebuild.start_build()`. Polls every 15 seconds via `codebuild.batch_get_builds()` until `buildStatus` is no longer `IN_PROGRESS`. Raises `TimeoutError` if the build does not finish within 30 minutes.

Terminal statuses: `SUCCEEDED`, `FAILED`, `FAULT`, `TIMED_OUT`, `STOPPED`.

### Step 6 — Download All 3 Reports

Only runs if `buildStatus == "SUCCEEDED"`. Each function constructs the S3 key from the build ID, downloads the JSON, and saves it locally with a timestamp.

| Function | S3 Key | Saved To |
|---|---|---|
| `download_aibom_report()` | `{build_prefix}/aibom-report.cdx.json` | `reports/aibom_aws_{region}_{repo}_{ts}.json` |
| `download_grype_report()` | `{build_prefix}/grype-report.json` | `sbom_reports/grype_aws_{region}_{repo}_{ts}.json` |
| `download_semgrep_report()` | `{build_prefix}/semgrep-report.json` | `sbom_reports/semgrep_aws_{region}_{repo}_{ts}.json` |

---

## Scanning Tools

| Tool | What It Does |
|---|---|
| **Grype** | Scans all package manifests (`requirements.txt`, `package.json`, `go.sum`, etc.) and matches against the NVD, GitHub Advisory, and vendor CVE databases. Outputs every known CVE with severity, fix version, and EPSS exploit probability. |
| **Semgrep** | Pattern-based code scanner. Uses `--config=auto` to load 300+ rules covering OWASP Top 10, hardcoded secrets, weak cryptography, SQL injection, XSS, and more. |
| **Cisco AIBOM** | Detects AI/ML components in source code: LLM model references, prompt templates, embeddings, AI framework imports, and secrets passed to AI APIs. Outputs a CycloneDX 1.6 SBOM. Uses `llama-3.3-70b-versatile` on Groq for intelligent analysis. |

---

## End Result

After a single `python main.py` run, for every repo in the account/region you get three local JSON files:

- **All known CVEs and vulnerabilities** in the repo's dependencies (Grype) → `sbom_reports/grype_aws_*.json`
- **All code-level security issues and bad patterns** (Semgrep) → `sbom_reports/semgrep_aws_*.json`
- **A full inventory of every AI/ML component** used in the codebase (Cisco AIBOM) → `reports/aibom_aws_*.json`

The raw reports also remain in S3 under `cytex-security-scan-reports/{build_id}/` for archival and audit purposes.
