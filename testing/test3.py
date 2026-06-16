from dotenv import load_dotenv
import requests
from requests.auth import HTTPBasicAuth
import json
import os
load_dotenv()

# in this file, we will fetch the file list for a repository in a project. We will use the repository ID to fetch the file list.
ORG = os.getenv("AZURE_DEVOPS_ORG")
PROJECT = os.getenv("AZURE_DEVOPS_PROJECT")
REPO_ID = os.getenv("AZURE_DEVOPS_REPO_ID")
PAT = os.getenv("AZURE_DEVOPS_PAT")

url = (
    f"https://dev.azure.com/"
    f"{ORG}/{PROJECT}/_apis/git/repositories/"
    f"{REPO_ID}/items"
    f"?recursionLevel=Full&api-version=7.1"
)

response = requests.get(
    url,
    auth=HTTPBasicAuth("", PAT)
)

print(response.status_code)
print(json.dumps(response.json(), indent=2))