import requests
from requests.auth import HTTPBasicAuth
import json
import os
from dotenv import load_dotenv
load_dotenv()

ORG = os.getenv("AZURE_DEVOPS_ORG")
PROJECT = os.getenv("AZURE_DEVOPS_PROJECT")
BUILD_ID = 1
PAT = os.getenv("AZURE_DEVOPS_PAT")

# we will fetch the build logs for a build using the build logs API. We will use the build ID to fetch the build logs. The build logs API is used to fetch the build logs for a build. We will use the build
url = (
    f"https://dev.azure.com/"
    f"{ORG}/{PROJECT}/_apis/build/builds/"
    f"{BUILD_ID}/logs?api-version=7.1"
)

response = requests.get(
    url,
    auth=HTTPBasicAuth("", PAT)
)

print("Status:", response.status_code)
print(json.dumps(response.json(), indent=2))