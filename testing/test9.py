import requests
from requests.auth import HTTPBasicAuth
import os 
from dotenv import load_dotenv
load_dotenv()

ORG = os.getenv("AZURE_DEVOPS_ORG")
PROJECT = os.getenv("AZURE_DEVOPS_PROJECT")
BUILD_ID = 1
LOG_ID = 10
PAT = os.getenv("AZURE_DEVOPS_PAT")

#  we will fetch the build log content for a build using the build logs API. We will use the build ID and log ID to fetch the build log content. The build logs API is used to fetch the build logs for a build. We will use the build ID and log ID to fetch the build log content.
url = (
    f"https://dev.azure.com/"
    f"{ORG}/{PROJECT}/_apis/build/builds/"
    f"{BUILD_ID}/logs/"
    f"{LOG_ID}"
    f"?api-version=7.1"
)

response = requests.get(
    url,
    auth=HTTPBasicAuth("", PAT)
)

print(response.status_code)
print(response.text)