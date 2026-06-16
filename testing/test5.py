import requests
from requests.auth import HTTPBasicAuth
import json
import os 
from dotenv import load_dotenv
load_dotenv()

ORG = os.getenv("AZURE_DEVOPS_ORG")
PROJECT = os.getenv("AZURE_DEVOPS_PROJECT")
PAT = os.getenv("AZURE_DEVOPS_PAT")

# we will fetch the pipeline list for a project using the pipelines API. We will use the project name to fetch the pipeline list.
url = (
    f"https://dev.azure.com/"
    f"{ORG}/{PROJECT}/_apis/pipelines"
    f"?api-version=7.1"
)

response = requests.get(
    url,
    auth=HTTPBasicAuth("", PAT)
)

print("Status:", response.status_code)
print(json.dumps(response.json(), indent=2))