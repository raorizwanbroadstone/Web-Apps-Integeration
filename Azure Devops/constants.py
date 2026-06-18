from dotenv import load_dotenv
import os

load_dotenv()

ORG = os.getenv("AZURE_DEVOPS_ORG")
PROJECT = os.getenv("AZURE_DEVOPS_PROJECT")
PAT = os.getenv("AZURE_DEVOPS_PAT")

API_VERSION = "7.1"

BASE_URL = f"https://dev.azure.com/{ORG}"

REPORT_DIR = "reports"
SBOM_DIR = "sbom_reports"