from dotenv import load_dotenv
import os

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise EnvironmentError("GROQ_API_KEY is not set in your .env file. Add it before running.")

BUCKET_NAME = os.getenv("AWS_S3_BUCKET", "cytex-security-scan-reports")
CODEBUILD_ROLE_NAME = os.getenv("CODEBUILD_ROLE_NAME", "cytex-codebuild-role")
CODEPIPELINE_ROLE_NAME = os.getenv("CODEPIPELINE_ROLE_NAME", "cytex-codepipeline-role")

REPORT_DIR = "reports"
SBOM_DIR = "sbom_reports"

# Shared naming 
RESOURCE_PREFIX = "cytex-scan"
COMMIT_MESSAGE = "Add Cytex security scanning pipeline"
