# Cytex Security Scanning — CI/CD Integration

Automated security scanning pipeline that targets every repository in your AWS CodeCommit or Azure DevOps organization with a single command. No per-repository setup required.

---

## Overview

The tool connects to your CI/CD platform, injects a `cytex.yml` pipeline definition into each repository, triggers a build, and downloads the results locally. Each repository is scanned with three tools running in parallel:

| Tool | Scans For |
|------|-----------|
| **Grype** | Known CVEs in dependencies |
| **Semgrep** | Code vulnerabilities and insecure patterns |
| **Cisco AIBOM** | AI/ML components and supply chain risks |

Reports are saved as timestamped JSON files:
- `reports/` — AIBOM reports
- `sbom_reports/` — Grype and Semgrep reports

---

## Project Structure

```
Web-Apps-Integeration/
├── AWS CodeCommit/        # AWS integration (CodeCommit + CodeBuild + CodePipeline)
│   ├── main.py
│   ├── codecommit.py
│   ├── constants.py
│   └── Readme.md
├── Azure Devops/          # Azure DevOps integration
│   ├── main.py
│   ├── azure.py
│   ├── constants.py
│   └── Readme.md
├── requirements.txt
└── .env                   # Credentials (never commit this)
```

---

## Requirements

**Python 3.8+** with dependencies:

```bash
pip install -r requirements.txt
```

---

## AWS CodeCommit

### How It Works

1. Auto-creates shared infrastructure on first run (S3 bucket, IAM roles — reused on every subsequent run)
2. Discovers all CodeCommit repositories in the configured region
3. Commits `cytex.yml` into each repository, creates a CodeBuild project and CodePipeline pipeline, and triggers a build
4. Downloads completed scan reports from S3 to local directories

### Configuration

Create a `.env` file inside `AWS CodeCommit/`:

```env
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
GROQ_API_KEY=your-groq-api-key
```

The IAM user must have these policies attached: `AWSCodeCommitFullAccess`, `AWSCodeBuildAdminAccess`, `AWSCodePipeline_FullAccess`, `AmazonS3FullAccess`, `IAMFullAccess`, `CloudWatchLogsFullAccess`.

A Groq API key is required by Cisco AIBOM — get one at [console.groq.com](https://console.groq.com).

### Run

```bash
cd "AWS CodeCommit"
python main.py
```

---

## Azure DevOps

### How It Works

1. Discovers all projects and repositories in the organization via the Azure DevOps REST API
2. Commits `cytex.yml` into each repository and creates a pipeline definition
3. Queues an immediate build run and waits for completion
4. Downloads and extracts scan artifacts locally

### Configuration

Create a `.env` file in the project root:

```env
AZURE_DEVOPS_ORG=your-organization-name
AZURE_DEVOPS_PAT=your-personal-access-token
```

The PAT requires **Code (Read & Write)** and **Build (Read & Execute)** scopes. Generate one at **Azure DevOps → Profile → Personal Access Tokens**.

### Run

```bash
cd "Azure Devops"
python main.py
```

---

## Notes

- A failed repository is logged and skipped — the remaining repositories continue scanning uninterrupted.
- AWS resources (`cytex-security-scan-reports` S3 bucket, `cytex-codebuild-role`, `cytex-codepipeline-role`) are created once and reused on every subsequent run.
- **Never commit `.env`** — it contains credentials. Add it to `.gitignore` and rotate any keys that have been exposed.

---

For detailed setup instructions, see the `Readme.md` inside each integration folder.
