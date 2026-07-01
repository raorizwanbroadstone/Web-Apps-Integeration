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

# Microsoft Entra ID (App Registration) credentials
DIRECTORY_ID=your-directory-tenant-id
APPLICATION_ID=your-application-client-id
SECRET_KEY=your-client-secret-value
```

This integration authenticates with a Microsoft Entra ID App Registration using the
OAuth client-credentials flow — no Personal Access Token is required. `DIRECTORY_ID`
is the tenant ID, `APPLICATION_ID` is the client ID, and `SECRET_KEY` is the client
secret value. The organization name is still needed for API routing.

## Groq API Key Setup

To let the pipeline run Cisco AIBOM, set `GROQ_API_KEY` in Azure DevOps as a secret variable:

1. Create a variable group in `Pipelines` -> `Library`
2. Add `GROQ_API_KEY`
3. Mark it secret
4. Link that variable group to the pipeline

The pipeline passes this value into the job as an environment variable and the script reads it as `$GROQ_API_KEY`.

The pipeline also includes a safe debug step that confirms the variable is present in the job without printing the secret itself.

---

## How to Set Up the App Registration

1. In the **Azure portal** → **Microsoft Entra ID** → **App registrations** → **New registration**. Copy the **Application (client) ID** and **Directory (tenant) ID**.
2. Under **Certificates & secrets** → **New client secret**, create a secret and copy its **value** (shown only once).
3. Put these into `.env` as `APPLICATION_ID`, `DIRECTORY_ID`, and `SECRET_KEY`.

The token is requested against the well-known Azure DevOps resource ID
(`499b84ac-1321-427f-aa17-267ca6975798`) using the `.default` scope, so no Entra API
permission grant or admin consent is required — authorization is governed entirely by
the service principal's membership and permissions inside the Azure DevOps organization
(next section).

## Grant the Service Principal Access in Azure DevOps

An App Registration cannot access Azure DevOps from credentials alone — the service
principal must be added to the organization and granted permissions:

1. **Organization Settings** → **Users** → **Add users**, enter the app registration by name / Application ID, and assign the **Basic** access level.
2. Grant it the same permissions a PAT would need by adding it to the appropriate security group(s):

| Scope | Permission | Required For |
|-------|-----------|--------------|
| Code | Read and write | Read repositories and commit `cytex.yml` |
| Build | Read and execute | Create pipelines, queue runs, download artifacts |

Creating pipeline *definitions* may require **Build Administrator** (or equivalent) at the
project level. If `create_pipeline` returns 403, escalate the service principal's build
permissions accordingly.

> **Note:** client secrets expire. When they do, token acquisition fails with a 401 at
> the login endpoint — rotate the secret in the portal and update `SECRET_KEY`.

---

## Usage

```bash
python main.py
```

The script prints progress for each repository as it runs. A failed repository is logged and skipped — the rest of the organization continues scanning.
