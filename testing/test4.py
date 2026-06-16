import requests
from requests.auth import HTTPBasicAuth
import os 
from dotenv import load_dotenv

load_dotenv()

ORG = os.getenv("AZURE_DEVOPS_ORG")
PROJECT = os.getenv("AZURE_DEVOPS_PROJECT")
REPO_ID = os.getenv("AZURE_DEVOPS_REPO_ID")
PAT = os.getenv("AZURE_DEVOPS_PAT")

# we will fetch requirements.txt file content from the repository using the items API. We will specify the path to the file and set includeContent to true to get the file content in the response.
url = (
    f"https://dev.azure.com/{ORG}/{PROJECT}"
    f"/_apis/git/repositories/{REPO_ID}/items"
    f"?path=/requirements.txt"
    f"&includeContent=true"
    f"&api-version=7.1"
)

response = requests.get(
    url,
    auth=HTTPBasicAuth("", PAT)
)

print(response.status_code)
print(response.text)