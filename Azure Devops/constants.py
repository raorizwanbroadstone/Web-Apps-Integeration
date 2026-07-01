import os
from dotenv import load_dotenv

load_dotenv()

# Microsoft Entra ID (App Registration) client-credentials auth.
TENANT_ID = os.getenv("DIRECTORY_ID")      # Directory (tenant) ID
CLIENT_ID = os.getenv("APPLICATION_ID")    # Application (client) ID
CLIENT_SECRET = os.getenv("SECRET_KEY")    # Client secret value


for _name, _value in (("DIRECTORY_ID", TENANT_ID),
                      ("APPLICATION_ID", CLIENT_ID),
                      ("SECRET_KEY", CLIENT_SECRET)):
    if not _value:
        raise ValueError(f"{_name} is required for Azure DevOps Entra ID authentication")

API_VERSION = "7.1"

BASE_URL = f"https://dev.azure.com/{ORG}"

REPORT_DIR = "reports"
SBOM_DIR = "sbom_reports"

# Shared naming
RESOURCE_PREFIX = "cytex-scan"
COMMIT_MESSAGE = "Add Cytex security scanning pipeline"