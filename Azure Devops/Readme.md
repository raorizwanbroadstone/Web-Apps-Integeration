# Azure DevOps Automated Security Scanning Pipeline

Scans every repository across your entire Azure DevOps organization with a single command. No manual setup per repository required.

---

## What It Does

1. Discovers all projects and repositories in the organization via the Azure DevOps API
2. Commits an `cytex.yml` security scanning pipeline to each repository
3. Creates the pipeline definition and queues an immediate build run
4. Waits for the build to complete, then downloads the scan results locally

Each repository is scanned with three tools running in parallel on an Ubuntu agent:

| Tool | Scans For | Output File |
|------|-----------|-------------|
| Grype | Known CVEs in dependencies | `grype-report.json` |
| Semgrep | Code vulnerabilities and bad patterns | `semgrep-report.json` |
| Cisco AIBOM | AI/ML components in the codebase | `aibom-report.cdx.json` |

Reports are saved locally as timestamped JSON files under `reports/` (AIBOM) and `sbom_reports/` (Grype, Semgrep).

---

## Requirements

**Python packages**

```
pip install requests python-dotenv
```

**`.env` file** in the project root:

```env
AZURE_DEVOPS_ORG=your-organization-name
AZURE_DEVOPS_PAT=your-personal-access-token
```

This integration uses Azure DevOps PAT authentication only. You do not need an application ID, directory ID, or client secret for this flow.

## Groq API Key Setup

To let the pipeline run Cisco AIBOM, set `GROQ_API_KEY` in Azure DevOps as a secret variable:

1. Create a variable group in `Pipelines` -> `Library`
2. Add `GROQ_API_KEY`
3. Mark it secret
4. Link that variable group to the pipeline

The pipeline passes this value into the job as an environment variable and the script reads it as `$GROQ_API_KEY`.

The pipeline also includes a safe debug step that confirms the variable is present in the job without printing the secret itself.

---

## How to Create a PAT

1. Sign in to Azure DevOps and click your profile picture (top right)
2. Go to **Personal Access Tokens** → **New Token**
3. Give it a name, set an expiry, and choose **Custom defined** under Scopes
4. Grant the following permissions:

| Scope | Permission | Required For |
|-------|-----------|--------------|
| Code | Read and write | Read repositories and commit `cytex.yml` |
| Build | Read and execute | Create pipelines, queue runs, download artifacts |

5. Click **Create** and copy the token — it will not be shown again
6. Paste it as `AZURE_DEVOPS_PAT` in your `.env` file

---

## Usage

```bash
python main.py
```

The script prints progress for each repository as it runs. A failed repository is logged and skipped — the rest of the organization continues scanning.
