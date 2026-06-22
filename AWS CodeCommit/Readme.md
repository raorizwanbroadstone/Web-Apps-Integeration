# AWS CodeCommit Automated Security Scanning Pipeline

Scans every repository in your AWS CodeCommit account with a single command. No manual setup per repository required.

---

## What It Does

1. Creates a shared S3 bucket and two IAM service roles on the first run (reused on every subsequent run)
2. Discovers all CodeCommit repositories in the configured region
3. Commits a `cytex.yml` pipeline definition into each repository
4. Creates a CodeBuild project and CodePipeline pipeline per repository, then triggers a build
5. Downloads scan results per repository to local directories once the build succeeds

Each repository is scanned with three tools:

| Tool | Scans For | Output File |
|------|-----------|-------------|
| Grype | Known CVEs in dependencies | `grype-report.json` |
| Semgrep | Code vulnerabilities and bad patterns | `semgrep-report.json` |
| Cisco AIBOM | AI/ML components in the codebase | `aibom-report.cdx.json` |

Reports are saved locally as timestamped JSON files under `reports/` (AIBOM) and `sbom_reports/` (Grype, Semgrep), one file per repository per tool.

---

## Requirements

**Python packages**

```bash
pip install -r requirements.txt
```

**`.env` file** in the `AWS Codecommit/` folder:

```env
AWS_DEFAULT_REGION=us-east-1
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

## Step 1 — Create AWS Access Keys

### Option A — Create a New IAM User (Recommended)

1. Go to **AWS Console → IAM → Users → Create user**
2. Enter a username and click through to **Create user**
3. Open the user → **Permissions tab → Add permissions → Attach policies directly**
4. Search for and attach each of the following policies:

| Policy | Required For |
|--------|-------------|
| `AWSCodeCommitFullAccess` | List repositories and commit `cytex.yml` |
| `AWSCodeBuildAdminAccess` | Create and manage CodeBuild projects |
| `AWSCodePipeline_FullAccess` | Create and execute pipelines |
| `AmazonS3FullAccess` | Create the report bucket, enable versioning, upload/download results |
| `IAMFullAccess` | Auto-create the CodeBuild and CodePipeline service roles |
| `CloudWatchLogsFullAccess` | CodeBuild log group creation |

5. Go to **Security credentials tab → Create access key**
6. Select **Application running outside AWS** → click through to **Create access key**
7. Copy the **Access key ID** → paste as `AWS_ACCESS_KEY_ID` in `.env`
8. Copy the **Secret access key** → paste as `AWS_SECRET_ACCESS_KEY` in `.env`

> The secret key is only shown once. Copy it immediately.

### Option B — Use an Existing User

Go to **IAM → Users → your user → Permissions tab** and attach the same policies listed above. Then go to **Security credentials → Create access key** to generate the key pair.

---

## Step 2 — Get a Groq API Key

1. Sign up or log in at [https://console.groq.com](https://console.groq.com)
2. Go to **API Keys → Create API Key**
3. Copy the key and paste it as `GROQ_API_KEY` in `.env`

The Groq key is required by Cisco AIBOM for AI-assisted analysis. The script will exit immediately with a clear error if it is missing.

---

## Step 3 — Create a CodeCommit Repository

You need at least one repository before running the script.

**Via AWS Console:** Go to **CodeCommit → Repositories → Create repository**, enter a name, and click **Create**.

**Via AWS CLI:**
```bash
aws codecommit create-repository --repository-name your-repo --region us-east-1
```

The repository can be empty — the script creates the first commit when it pushes `cytex.yml`.

---

## What Gets Created Automatically

The script auto-creates the following AWS resources on the first run and reuses them on every subsequent run:

| Resource | Default Name | Purpose |
|----------|-------------|---------|
| S3 bucket | `cytex-security-scan-reports` | Stores raw scan reports uploaded by each CodeBuild run |
| IAM role | `cytex-codebuild-role` | Allows CodeBuild to read from CodeCommit, write to S3, and publish logs |
| IAM role | `cytex-codepipeline-role` | Allows CodePipeline to trigger CodeBuild and manage S3 artifacts |

---

## Usage

```bash
python main.py
```

The script prints progress for each repository as it runs. A failed repository is logged and skipped — the rest continue scanning.
