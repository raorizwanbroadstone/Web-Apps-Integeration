import requests
from requests.auth import HTTPBasicAuth
import os
from dotenv import load_dotenv
load_dotenv()

ORG = os.getenv("AZURE_DEVOPS_ORG")
PAT = os.getenv("AZURE_DEVOPS_PAT")

url = f"https://dev.azure.com/{ORG}/_apis/projects?api-version=7.1"

response = requests.get(
    url,
    auth=HTTPBasicAuth("", PAT)
)

print("Status:", response.status_code)
print(response.text)