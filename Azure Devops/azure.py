import base64
import time
import requests
from requests.auth import HTTPBasicAuth
import io
import json
import zipfile
import os
from datetime import datetime, timezone
from constants import BASE_URL, API_VERSION, PAT, REPORT_DIR, SBOM_DIR

AUTH = HTTPBasicAuth("", PAT)

# Azure DevOps requires the old object ID when pushing to a branch.
# This sentinel value is used when the branch does not yet exist.
ZERO_SHA = "0000000000000000000000000000000000000000"


def http_get(url):
    response = requests.get(url, auth=AUTH, timeout=60)
    response.raise_for_status()
    return response


def fetch_json(url):
    return http_get(url).json()


def save_json_file(data, directory, filename):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2)
    return path


# Discovery

def get_projects():
    url = f"{BASE_URL}/_apis/projects?api-version={API_VERSION}"
    return fetch_json(url).get("value", [])


def get_repos(project):
    url = f"{BASE_URL}/{project}/_apis/git/repositories?api-version={API_VERSION}"
    return fetch_json(url).get("value", [])


# Pipeline YAML injection

def get_branch_sha(project, repo_id, branch):
    """Returns the current HEAD SHA for the branch, or ZERO_SHA if the branch does not exist."""
    url = (
        f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/refs"
        f"?filter=heads/{branch}&api-version={API_VERSION}"
    )
    refs = fetch_json(url).get("value", [])
    return refs[0]["objectId"] if refs else ZERO_SHA


def get_existing_pipeline_yaml(project, repo_id, branch):
    """Returns the current content of cytex.yml, or None if the file does not exist."""
    url = (
        f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/items"
        f"?path=/cytex.yml&versionDescriptor.version={branch}"
        f"&$format=text&api-version={API_VERSION}"
    )
    try:
        return http_get(url).text
    except requests.HTTPError as http_error:
        if http_error.response.status_code == 404:
            return None
        raise


def push_pipeline_yaml(project, repo_id, default_branch, yaml_content):
    """Commits cytex.yml to the repository's default branch.

    Returns None if the file already exists with identical content, skipping the commit.
    """
    branch = default_branch.replace("refs/heads/", "")
    existing_content = get_existing_pipeline_yaml(project, repo_id, branch)

    if existing_content is not None and existing_content.strip() == yaml_content.strip():
        return None

    parent_sha = get_branch_sha(project, repo_id, branch)
    change_type = "edit" if existing_content is not None else "add"

    encoded_content = base64.b64encode(yaml_content.encode("utf-8")).decode("ascii")

    url = f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/pushes?api-version={API_VERSION}"
    body = {
        "refUpdates": [{"name": f"refs/heads/{branch}", "oldObjectId": parent_sha}],
        "commits": [{
            "comment": "Add security scanning pipeline [skip ci]",
            "changes": [{
                "changeType": change_type,
                "item": {"path": "/cytex.yml"},
                "newContent": {
                    "content": encoded_content,
                    "contentType": "base64Encoded",
                },
            }],
        }],
    }
    response = requests.post(url, auth=AUTH, json=body, timeout=60)
    response.raise_for_status()
    return response.json()


# Pipeline definition and run management

def find_pipeline_by_name(project, name):
    """Returns the existing pipeline definition if one with the given name exists, else None."""
    url = f"{BASE_URL}/{project}/_apis/pipelines?api-version={API_VERSION}"
    pipelines = fetch_json(url).get("value", [])
    return next((pipeline for pipeline in pipelines if pipeline["name"] == name), None)


def create_pipeline(project, repo_id, repo_name, yaml_path="cytex.yml"):
    """Creates the pipeline definition, or returns the existing one if already present."""
    pipeline_name = f"cytex-scan-{repo_name}"
    existing_pipeline = find_pipeline_by_name(project, pipeline_name)
    if existing_pipeline:
        return existing_pipeline

    url = f"{BASE_URL}/{project}/_apis/pipelines?api-version={API_VERSION}"
    body = {
        "name": pipeline_name,
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
    response = requests.post(url, auth=AUTH, json=body, timeout=60)
    response.raise_for_status()
    return response.json()


def queue_pipeline_run(project, pipeline_id):
    url = f"{BASE_URL}/{project}/_apis/pipelines/{pipeline_id}/runs?api-version={API_VERSION}"
    response = requests.post(url, auth=AUTH, json={}, timeout=60)
    response.raise_for_status()
    return response.json()


# Build polling

def get_pipeline_run(project, pipeline_id, run_id):
    url = f"{BASE_URL}/{project}/_apis/pipelines/{pipeline_id}/runs/{run_id}?api-version={API_VERSION}"
    return fetch_json(url)


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


# Legacy single-project helpers retained for direct build inspection

def get_builds(project):
    url = f"{BASE_URL}/{project}/_apis/build/builds?api-version={API_VERSION}"
    return fetch_json(url)


def get_latest_build(project):
    builds = get_builds(project).get("value", [])
    return max(builds, key=lambda build: build["id"]) if builds else None


def get_build_artifacts(build_id, project):
    url = f"{BASE_URL}/{project}/_apis/build/builds/{build_id}/artifacts?api-version={API_VERSION}"
    return fetch_json(url)


# Artifact download

def download_artifact_zip_as_json(build_id, project, artifact_name):
    """Downloads a pipeline artifact ZIP and returns the first JSON file found inside it."""
    artifacts = get_build_artifacts(build_id, project).get("value", [])
    target_artifact = next((artifact for artifact in artifacts if artifact["name"] == artifact_name), None)
    if not target_artifact:
        return None, None

    response = requests.get(target_artifact["resource"]["downloadUrl"], auth=AUTH, timeout=120)
    response.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_archive:
        json_filename = next((name for name in zip_archive.namelist() if name.endswith(".json")), None)
        if not json_filename:
            return None, None
        return json.loads(zip_archive.read(json_filename).decode("utf-8")), json_filename


def download_aibom_report(build_id, organization, project, repo_name):
    data, _ = download_artifact_zip_as_json(build_id, project, "aibom-report")
    if data is None:
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, f"aibom_{organization}_{project}_{repo_name}_{timestamp}.json")
    with open(path, "w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2)
    return path


def download_grype_report(build_id, organization, project, repo_name):
    data, _ = download_artifact_zip_as_json(build_id, project, "grype-report")
    if data is None:
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return save_json_file(data, SBOM_DIR, f"grype_{organization}_{project}_{repo_name}_{timestamp}.json")


def download_semgrep_report(build_id, organization, project, repo_name):
    data, _ = download_artifact_zip_as_json(build_id, project, "semgrep-report")
    if data is None:
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return save_json_file(data, SBOM_DIR, f"semgrep_{organization}_{project}_{repo_name}_{timestamp}.json")
