import requests
from requests.auth import HTTPBasicAuth
import io
import json
import zipfile
import os
from datetime import datetime
from constants import BASE_URL, PROJECT, API_VERSION, PAT, REPORT_DIR

AUTH = HTTPBasicAuth("", PAT)


def _get(url):
    r = requests.get(url, auth=AUTH, timeout=60)
    r.raise_for_status()
    return r


def get_json(url):
    return _get(url).json()


def get_builds():
    url = f"{BASE_URL}/{PROJECT}/_apis/build/builds?api-version={API_VERSION}"
    return get_json(url)


def get_latest_build():
    builds = get_builds().get("value", [])
    return max(builds, key=lambda x: x["id"]) if builds else None


def get_build_artifacts(build_id):
    url = f"{BASE_URL}/{PROJECT}/_apis/build/builds/{build_id}/artifacts?api-version={API_VERSION}"
    return get_json(url)


def download_aibom_report(build_id, org, project, repo_name):
    artifacts = get_build_artifacts(build_id).get("value", [])

    target = next(
        (a for a in artifacts if a["name"] == "aibom-report"),
        None
    )

    if not target:
        return None

    r = requests.get(
        target["resource"]["downloadUrl"],
        auth=AUTH,
        timeout=120
    )
    r.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        json_file = next(
            (n for n in z.namelist() if n.endswith(".json")),
            None
        )

        if not json_file:
            return None

        data = json.loads(z.read(json_file).decode("utf-8"))

    os.makedirs(REPORT_DIR, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    filename = f"aibom_{org}_{project}_{repo_name}_{ts}.json"
    path = os.path.join(REPORT_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return path