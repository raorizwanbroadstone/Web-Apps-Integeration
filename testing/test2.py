import requests
from requests.auth import HTTPBasicAuth
import json
import os
from dotenv import load_dotenv
load_dotenv()

# we fetched the project list in test.py, now we will fetch the repository list for a project in test2.py
ORG = os.getenv("AZURE_DEVOPS_ORG")
PROJECT = os.getenv("AZURE_DEVOPS_PROJECT")
PAT = os.getenv("AZURE_DEVOPS_PAT")

url = f"https://dev.azure.com/{ORG}/{PROJECT}/_apis/git/repositories?api-version=7.1"

response = requests.get(
    url,
    auth=HTTPBasicAuth("", PAT)
)

print("Status:", response.status_code)
print(json.dumps(response.json(), indent=2))