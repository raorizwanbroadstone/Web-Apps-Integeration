import requests
from requests.auth import HTTPBasicAuth
import json
import os
from dotenv import load_dotenv
load_dotenv()

ORG = os.getenv("AZURE_DEVOPS_ORG")
PROJECT = os.getenv("AZURE_DEVOPS_PROJECT")
PIPELINE_ID = 1
PAT = os.getenv("AZURE_DEVOPS_PAT")

# we will fetch the pipeline run list for a pipeline using the pipeline runs API. We will use the pipeline ID to fetch the pipeline run list.
url = (
    f"https://dev.azure.com/"
    f"{ORG}/{PROJECT}/_apis/pipelines/"
    f"{PIPELINE_ID}/runs"
    f"?api-version=7.1"
)

response = requests.get(
    url,
    auth=HTTPBasicAuth("", PAT)
)

print("Status:", response.status_code)
print(json.dumps(response.json(), indent=2))