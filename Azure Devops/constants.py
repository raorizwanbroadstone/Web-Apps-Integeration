import os
from dotenv import load_dotenv

load_dotenv()

ORG = os.getenv("AZURE_DEVOPS_ORG")
PAT = os.getenv("AZURE_DEVOPS_PAT")

if not ORG:
    raise ValueError("AZURE_DEVOPS_ORG is required for Azure DevOps PAT authentication")

if not PAT:
    raise ValueError("AZURE_DEVOPS_PAT is required for Azure DevOps PAT authentication")

API_VERSION = "7.1"

BASE_URL = f"https://dev.azure.com/{ORG}"

REPORT_DIR = "reports"
SBOM_DIR = "sbom_reports"