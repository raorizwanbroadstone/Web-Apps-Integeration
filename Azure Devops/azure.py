import base64
import time
import requests
from requests.auth import HTTPBasicAuth
import io
import json
import zipfile
import os
from constants import (
    BASE_URL,
    API_VERSION,
    PAT,
    REPORT_DIR,
    SBOM_DIR,
    RESOURCE_PREFIX,
    COMMIT_MESSAGE,
)

AUTH = HTTPBasicAuth("", PAT)

# Azure DevOps requires the old object ID when pushing to a branch.This sentinel value is used when the branch does not yet exist.
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


def scan_resource_name(repo_name):
    """The name used for the per-repo pipeline definition.

    Built from RESOURCE_PREFIX so the `cytex-scan-<repo>` convention lives in a single place.
    """
    return f"{RESOURCE_PREFIX}-{repo_name}"


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
            "comment": COMMIT_MESSAGE,
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
    pipeline_name = scan_resource_name(repo_name)
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


def poll_build_completion(project, pipeline_id, run_id, timeout=600):
    elapsed = 0
    initial_interval = 100
    followup_interval = 60

    while elapsed < timeout:
        run = get_pipeline_run(project, pipeline_id, run_id)
        state = run.get("state")
        if state == "completed":
            return run

        if elapsed == 0:
            print(f"    run {run_id} -> {state}")
        else:
            print(f"    [{elapsed}s] run {run_id} -> {state}")

        interval = initial_interval if elapsed == 0 else followup_interval
        time.sleep(interval)
        elapsed += interval

    raise TimeoutError(f"Run {run_id} did not complete within {timeout}s")


# Artifact download

def get_build_artifacts(build_id, project):
    url = f"{BASE_URL}/{project}/_apis/build/builds/{build_id}/artifacts?api-version={API_VERSION}"
    return fetch_json(url)


def download_report(build_id, project, artifact_name):
    """Downloads a pipeline artifact ZIP and returns the first JSON file inside it, or None."""
    artifacts = get_build_artifacts(build_id, project).get("value", [])
    target_artifact = next((artifact for artifact in artifacts if artifact["name"] == artifact_name), None)
    if not target_artifact:
        return None

    response = requests.get(target_artifact["resource"]["downloadUrl"], auth=AUTH, timeout=120)
    response.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_archive:
        json_filename = next((name for name in zip_archive.namelist() if name.endswith(".json")), None)
        if not json_filename:
            return None
        return json.loads(zip_archive.read(json_filename).decode("utf-8"))


# Each download_* function fetches one report and saves it locally, returning the saved path
# (or None if the artifact is missing). The timestamp is passed in by the caller so all three
# reports for a single repo share one timestamp instead of drifting between calls.

def download_aibom_report(build_id, organization, project, repo_name, timestamp):
    data = download_report(build_id, project, "aibom-report")
    if data is None:
        return None
    return save_json_file(data, REPORT_DIR, f"aibom_azure_{organization}_{project}_{repo_name}_{timestamp}.json")


def download_grype_report(build_id, organization, project, repo_name, timestamp):
    data = download_report(build_id, project, "grype-report")
    if data is None:
        return None
    return save_json_file(data, SBOM_DIR, f"grype_azure_{organization}_{project}_{repo_name}_{timestamp}.json")


def download_semgrep_report(build_id, organization, project, repo_name, timestamp):
    data = download_report(build_id, project, "semgrep-report")
    if data is None:
        return None
    return save_json_file(data, SBOM_DIR, f"semgrep_azure_{organization}_{project}_{repo_name}_{timestamp}.json")
