# AWS CodeCommit Automated Security Scanning Pipeline

Scans every CodeCommit repository across all regions enabled in your AWS account with a single command. No region config, no per-repository setup.

---

## What It Does

1. Creates two IAM service roles on the first run and reuses them afterwards
2. Discovers every enabled region that supports CodeCommit
3. For each region with repositories, creates a per-region S3 bucket, commits a `cytex.yml` pipeline into each repo, builds a CodeBuild project plus CodePipeline, and runs a scan
4. Downloads the results to local folders once each build succeeds

Each repository is scanned with three tools:

| Tool | Scans For | Output File |
|------|-----------|-------------|
| Grype | Known CVEs in dependencies | `grype-report.json` |
| Semgrep | Code vulnerabilities and bad patterns | `semgrep-report.json` |
| Cisco AIBOM | AI/ML components in the codebase | `aibom-report.cdx.json` |

Reports are saved as timestamped JSON under `reports/` (AIBOM) and `sbom_reports/` (Grype, Semgrep), tagged with the region and repository name.

---

## Requirements

**Python packages**

```bash
pip install -r requirements.txt
```

**`.env` file** in this folder - only the access keys are needed. The region is auto-discovered, and the Groq key is read from this same `.env` file and pushed into CodeBuild automatically:

```env
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
GROQ_API_KEY=your-groq-api-key
```

Optional overrides (defaults shown):

```env
AWS_S3_BUCKET=cytex-security-scan-reports
CODEBUILD_ROLE_NAME=cytex-codebuild-role
CODEPIPELINE_ROLE_NAME=cytex-codepipeline-role
```

---

## Step 1 - Create the IAM Policy

The script provisions buckets, roles, and pipelines, so it needs write access. Use the least-privilege policy included in this folder.

1. Go to AWS Console -> IAM -> Policies -> Create policy
2. Select the JSON tab and paste the full contents of `cytex-codecommit-policy.json`
3. Click Next, name it `CytexCodeCommitScan`, and click Create policy

> The policy includes `ec2:DescribeRegions` so the script scans only your enabled regions. It is optional - without it the script still works but probes all CodeCommit regions, which is slower.

---

## Step 2 - Create the User and Access Keys

1. Go to IAM -> Users -> Create user, set a username, click Next
2. Choose Attach policies directly, search for `CytexCodeCommitScan`, select it, and create the user
3. Open the user -> Security credentials -> Create access key
4. Choose Application running outside AWS, click through to Create access key
5. Copy the Access key ID into `AWS_ACCESS_KEY_ID` in `.env`
6. Copy the Secret access key into `AWS_SECRET_ACCESS_KEY` in `.env` (shown only once)
7. Add `GROQ_API_KEY` to `.env` if you want the AIBOM step to run successfully

---

## Step 3 - Run the Script

```bash
python main.py
```

The script prints progress per region and per repository. Disabled regions and failed repositories are skipped with a message; the rest continue.

---

## What Gets Created Automatically

| Resource | Default Name | Purpose |
|----------|-------------|---------|
| IAM role | `cytex-codebuild-role` | Lets CodeBuild read CodeCommit, write S3, publish logs |
| IAM role | `cytex-codepipeline-role` | Lets CodePipeline trigger CodeBuild and manage S3 artifacts |
| S3 bucket | `cytex-security-scan-reports-<region>` | One per scanned region |

