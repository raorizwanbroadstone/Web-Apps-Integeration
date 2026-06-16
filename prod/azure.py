import base64
import time
import requests
from requests.auth import HTTPBasicAuth
import io
import json
import zipfile
import os
from datetime import datetime, timezone
from constants import BASE_URL, PROJECT, API_VERSION, PAT, REPORT_DIR, SBOM_DIR

AUTH = HTTPBasicAuth("", PAT)

_ZERO_SHA = "0000000000000000000000000000000000000000"


def _get(url):
    r = requests.get(url, auth=AUTH, timeout=60)
    r.raise_for_status()
    return r


def get_json(url):
    return _get(url).json()


def _save_json(data, directory, filename):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


# ── Discovery ─────────────────────────────────────────────────────────────────

def get_projects():
    url = f"{BASE_URL}/_apis/projects?api-version={API_VERSION}"
    return get_json(url).get("value", [])


def get_repos(project):
    url = f"{BASE_URL}/{project}/_apis/git/repositories?api-version={API_VERSION}"
    return get_json(url).get("value", [])


# ── Pipeline YAML injection ───────────────────────────────────────────────────

def _get_branch_sha(project, repo_id, branch):
    """Returns the current HEAD SHA for a branch, or zero SHA if branch doesn't exist yet."""
    url = (
        f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/refs"
        f"?filter=heads/{branch}&api-version={API_VERSION}"
    )
    refs = get_json(url).get("value", [])
    return refs[0]["objectId"] if refs else _ZERO_SHA


def _yaml_exists(project, repo_id, branch):
    """Returns True if azure-pipelines.yml already exists on the branch."""
    url = (
        f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/items"
        f"?path=/azure-pipelines.yml&versionDescriptor.version={branch}"
        f"&api-version={API_VERSION}"
    )
    try:
        _get(url)
        return True
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            return False
        raise


def push_pipeline_yaml(project, repo_id, default_branch, yaml_content):
    """Commits azure-pipelines.yml to the repo's default branch."""
    branch = default_branch.replace("refs/heads/", "")
    old_sha = _get_branch_sha(project, repo_id, branch)
    change_type = "edit" if _yaml_exists(project, repo_id, branch) else "add"

    encoded = base64.b64encode(yaml_content.encode("utf-8")).decode("ascii")

    url = f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/pushes?api-version={API_VERSION}"
    body = {
        "refUpdates": [{"name": f"refs/heads/{branch}", "oldObjectId": old_sha}],
        "commits": [{
            "comment": "Add security scanning pipeline [skip ci]",
            "changes": [{
                "changeType": change_type,
                "item": {"path": "/azure-pipelines.yml"},
                "newContent": {
                    "content": encoded,
                    "contentType": "base64Encoded",
                },
            }],
        }],
    }
    r = requests.post(url, auth=AUTH, json=body, timeout=60)
    r.raise_for_status()
    return r.json()


# ── Pipeline definition + run ─────────────────────────────────────────────────

def create_pipeline(project, repo_id, repo_name, yaml_path="azure-pipelines.yml"):
    url = f"{BASE_URL}/{project}/_apis/pipelines?api-version={API_VERSION}"
    body = {
        "name": f"cytex-scan-{repo_name}",
        "folder": "\\",
        "configuration": {
            "type": "yaml",
            "path": f"/{yaml_path}",
            "repository": {
                "id": repo_id,
                "type": "azureReposGit",
            },
        },
    }
    r = requests.post(url, auth=AUTH, json=body, timeout=60)
    r.raise_for_status()
    return r.json()


def queue_pipeline_run(project, pipeline_id):
    url = f"{BASE_URL}/{project}/_apis/pipelines/{pipeline_id}/runs?api-version={API_VERSION}"
    r = requests.post(url, auth=AUTH, json={}, timeout=60)
    r.raise_for_status()
    return r.json()


# ── Build polling ─────────────────────────────────────────────────────────────

def get_pipeline_run(project, pipeline_id, run_id):
    url = f"{BASE_URL}/{project}/_apis/pipelines/{pipeline_id}/runs/{run_id}?api-version={API_VERSION}"
    return get_json(url)


def poll_build_completion(project, pipeline_id, run_id, interval=15, timeout=600):
    elapsed = 0
    while elapsed < timeout:
        run = get_pipeline_run(project, pipeline_id, run_id)
        state = run.get("state")
        if state == "completed":
            return run
        print(f"    [{elapsed}s] run {run_id} -> {state}")
        time.sleep(interval)
        elapsed += interval
    raise TimeoutError(f"Run {run_id} did not complete within {timeout}s")


# ── Legacy single-project helpers ─────────────────────────────────────────────

def get_builds(project=PROJECT):
    url = f"{BASE_URL}/{project}/_apis/build/builds?api-version={API_VERSION}"
    return get_json(url)


def get_latest_build(project=PROJECT):
    builds = get_builds(project).get("value", [])
    return max(builds, key=lambda x: x["id"]) if builds else None


def get_build_artifacts(build_id, project=PROJECT):
    url = f"{BASE_URL}/{project}/_apis/build/builds/{build_id}/artifacts?api-version={API_VERSION}"
    return get_json(url)


# ── Artifact download ─────────────────────────────────────────────────────────

def _download_artifact_json(build_id, project, artifact_name):
    """Downloads a ZIP artifact and returns the first JSON file inside it."""
    artifacts = get_build_artifacts(build_id, project).get("value", [])
    target = next((a for a in artifacts if a["name"] == artifact_name), None)
    if not target:
        return None, None

    r = requests.get(target["resource"]["downloadUrl"], auth=AUTH, timeout=120)
    r.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        json_file = next((n for n in z.namelist() if n.endswith(".json")), None)
        if not json_file:
            return None, None
        return json.loads(z.read(json_file).decode("utf-8")), json_file


def download_aibom_report(build_id, org, project, repo_name):
    data, _ = _download_artifact_json(build_id, project, "aibom-report")
    if data is None:
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, f"aibom_{org}_{project}_{repo_name}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def download_grype_report(build_id, org, project, repo_name):
    data, _ = _download_artifact_json(build_id, project, "grype-report")
    if data is None:
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return _save_json(data, SBOM_DIR, f"grype_{org}_{project}_{repo_name}_{ts}.json")


def download_semgrep_report(build_id, org, project, repo_name):
    data, _ = _download_artifact_json(build_id, project, "semgrep-report")
    if data is None:
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return _save_json(data, SBOM_DIR, f"semgrep_{org}_{project}_{repo_name}_{ts}.json")
