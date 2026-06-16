# Azure DevOps Automated Security Scanning Pipeline

## Overview

This is a fully automated security scanning pipeline for Azure DevOps. Run one command (`python main.py`) and it scans every repository across your entire Azure DevOps organization — no manual setup required per repo.

---

## Entry Point — `main.py`

### Step 1 — Discover Everything

Calls `get_projects()` which hits:

```
GET https://dev.azure.com/cytex-demo/_apis/projects
```

Returns every project in the org. Then for each project calls `get_repos(project)`:

```
GET https://dev.azure.com/cytex-demo/{project}/_apis/git/repositories
```

Returns every Git repository inside that project. The loop is: **every project → every repo → full scan**.

### Step 2 — Per Repo: call `scan_repo()`

Everything below happens once per repo, wrapped in a `try/except` so one failure never stops the rest.

---

## Inside `scan_repo()` — `main.py:79`

### Step 2a — Push the Pipeline YAML

Calls `push_pipeline_yaml()` from `azure.py`. Internally it:

- Fetches the repo's current `main` branch HEAD SHA via the Refs API (required because Azure's Git push API requires you to prove you know the current state before writing)
- Checks if `azure-pipelines.yml` already exists — uses `edit` if yes, `add` if no
- Base64-encodes the YAML content and POSTs it as a commit:

```
POST /git/repositories/{repo_id}/pushes
```

The commit message includes `[skip ci]` to prevent the push itself from triggering any existing pipelines.

The committed YAML defines a 3-tool security scan running on `ubuntu-latest`:

| Tool | What It Scans | Output |
|------|--------------|--------|
| **Grype** | Known CVEs in dependencies | `grype-report.json` |
| **Semgrep** | Code vulnerabilities / bad patterns | `semgrep-report.json` |
| **Cisco AIBOM** | AI/ML components in the codebase | `aibom-report.cdx.json` |

All three outputs are published as pipeline artifacts at the end.

### Step 2b — Create the Pipeline Definition

Calls `create_pipeline()` — POSTs to:

```
POST https://dev.azure.com/cytex-demo/{project}/_apis/pipelines
```

This registers a pipeline named `cytex-scan-{repo_name}` in Azure DevOps, pointing to the `azure-pipelines.yml` just committed. At this point no build runs yet — it's just the definition.

### Step 2c — Queue a Run

Calls `queue_pipeline_run()` — POSTs to:

```
POST https://dev.azure.com/cytex-demo/{project}/_apis/pipelines/{id}/runs
```

This triggers an immediate build. Azure spins up an Ubuntu agent, checks out the repo, installs the three tools, runs the scans, and publishes the artifacts.

### Step 2d — Poll Until Complete

Calls `poll_build_completion()` which loops every 15 seconds:

```
GET /_apis/pipelines/{id}/runs/{runId}
```

Checks the `state` field. When `state == "completed"` it stops. If it doesn't complete within 600 seconds it raises a `TimeoutError`. Prints elapsed time each tick so you can watch progress live.

### Step 2e — Download All 3 Artifacts

Only runs if the build result is `"succeeded"`. Each function follows the same pattern via the shared `_download_artifact_json()` helper:

1. Fetches the artifact list for the build
2. Finds the target artifact by name
3. Downloads the ZIP file from Azure's artifact download URL
4. Extracts the JSON file from inside the ZIP
5. Saves it locally with a timestamped filename

| Function | Artifact Name | Saved To |
|----------|--------------|----------|
| `download_aibom_report()` | `aibom-report` | `reports/aibom_{org}_{project}_{repo}_{ts}.json` |
| `download_grype_report()` | `grype-report` | `sbom_reports/grype_{org}_{project}_{repo}_{ts}.json` |
| `download_semgrep_report()` | `semgrep-report` | `sbom_reports/semgrep_{org}_{project}_{repo}_{ts}.json` |

---

## Configuration — `constants.py`

All credentials and settings are loaded from `.env`:

| Variable | Value | Purpose |
|----------|-------|---------|
| `AZURE_DEVOPS_ORG` | `cytex-demo` | The Azure DevOps org |
| `AZURE_DEVOPS_PAT` | `***` | Personal Access Token for auth |
| `API_VERSION` | `7.1` | Azure DevOps REST API version |
| `BASE_URL` | `https://dev.azure.com/cytex-demo` | Root URL for all API calls |

### Required PAT Permissions

When creating the PAT in Azure DevOps (**User Settings → Personal Access Tokens → New Token**), select **Custom defined** and grant the following scopes:

| Scope | Permission | Why |
|-------|-----------|-----|
| **Code** | Read & write | Read repo list + commit `azure-pipelines.yml` |
| **Build** | Read & execute | Create pipeline definitions, queue runs, poll status, download artifacts |

> Both are required. Missing either will cause 401/403 errors at the corresponding step.

---

## End Result

After a single `python main.py` run, for every repo in the org you get three local JSON files containing:

- **All known CVEs and vulnerabilities** in the repo's dependencies (Grype)
- **All code-level security issues and bad patterns** (Semgrep)
- **A full inventory of every AI/ML component** used in the codebase (Cisco AIBOM)