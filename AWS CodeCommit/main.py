import botocore.exceptions
from datetime import datetime, timezone
from codecommit import (
    configure_region,
    get_codecommit_regions,
    get_repos,
    get_default_branch,
    scan_resource_name,
    ensure_bucket,
    ensure_codebuild_role,
    ensure_codepipeline_role,
    push_buildspec,
    create_codebuild_project,
    create_or_get_pipeline,
    start_pipeline_execution,
    poll_pipeline_completion,
    get_build_id_from_execution,
    download_aibom_report,
    download_grype_report,
    download_semgrep_report,
)
from constants import BUCKET_NAME, CODEBUILD_ROLE_NAME, CODEPIPELINE_ROLE_NAME

BUILDSPEC_YAML = """\
version: 0.2

phases:
  install:
    commands:
      - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
      - python3 -m pip install --upgrade pip
      - python3 -m pip install semgrep
      - python3 -m pip install --pre "cisco-aibom[agentic]==1.0.0rc2" langchain-groq
      - mkdir -p ~/.aibom/catalogs
      - curl -L -o ~/.aibom/catalogs/aibom_catalog-1.0.0rc2.duckdb https://github.com/cisco-ai-defense/aibom/releases/download/1.0.0rc2/aibom_catalog-1.0.0rc2.duckdb

  build:
    commands:
      - grype dir:. -o json > grype-report.json
      - semgrep --config=auto . --json > semgrep-report.json
      - cisco-aibom analyze . -o cyclonedx -O aibom-report.cdx.json --llm-model llama-3.3-70b-versatile --llm-provider groq --llm-api-key "$GROQ_API_KEY"

  post_build:
    commands:
      - BUILD_PATH=$(echo "$CODEBUILD_BUILD_ID" | tr ':' '/')
      - aws s3 cp grype-report.json "s3://${BUCKET_NAME}/${BUILD_PATH}/grype-report.json"
      - aws s3 cp semgrep-report.json "s3://${BUCKET_NAME}/${BUILD_PATH}/semgrep-report.json"
      - aws s3 cp aibom-report.cdx.json "s3://${BUCKET_NAME}/${BUILD_PATH}/aibom-report.cdx.json"

artifacts:
  files:
    - grype-report.json
    - semgrep-report.json
    - aibom-report.cdx.json
  discard-paths: yes
"""


def scan_repo(repo_name, default_branch, region, bucket_name, codebuild_role_arn, codepipeline_role_arn):
    print(f"\n    Repo: {repo_name}")

    pushed = push_buildspec(repo_name, default_branch, BUILDSPEC_YAML)
    if pushed is None:
        print(f"    Buildspec already up to date, skipping commit")
    else:
        print(f"    Buildspec pushed to {default_branch}")

    create_codebuild_project(repo_name, codebuild_role_arn, bucket_name)
    print(f"    CodeBuild project ready: {scan_resource_name(repo_name)}")

    pipeline_name = create_or_get_pipeline(repo_name, default_branch, codepipeline_role_arn, bucket_name)
    print(f"    Pipeline ready: {pipeline_name}")

    execution_id = start_pipeline_execution(pipeline_name)
    print(f"    Execution started: {execution_id}")

    pipeline_status = poll_pipeline_completion(pipeline_name, execution_id)
    print(f"    Pipeline completed: {pipeline_status}")

    if pipeline_status != "Succeeded":
        print(f"    Skipping artifact fetch (pipeline {pipeline_status})")
        return

    build_id = get_build_id_from_execution(pipeline_name, execution_id)
    if not build_id:
        print(f"    Could not retrieve CodeBuild build ID, skipping fetch")
        return

    # One timestamp shared by all three reports so they sort together for the repo.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    aibom_path = download_aibom_report(build_id, bucket_name, region, repo_name, timestamp)
    if aibom_path:
        print(f"    AIBOM:   {aibom_path}")

    grype_path = download_grype_report(build_id, bucket_name, region, repo_name, timestamp)
    if grype_path:
        print(f"    Grype:   {grype_path}")

    semgrep_path = download_semgrep_report(build_id, bucket_name, region, repo_name, timestamp)
    if semgrep_path:
        print(f"    Semgrep: {semgrep_path}")


def scan_region(region, codebuild_role_arn, codepipeline_role_arn):
    """Scans every CodeCommit repo in one region. Returns the number of repos scanned."""
    configure_region(region)

    try:
        repos = get_repos()
    except botocore.exceptions.ClientError as client_error:
        # Region is disabled for this account, or the keys lack access there -- skip it.
        print(f"  [{region}] skipped: {client_error.response['Error']['Code']}")
        return 0
    except botocore.exceptions.ConnectionError as connection_error:
        # Opt-in regions that are not enabled refuse/time out at the TCP level.
        # ConnectionError is the botocore base for EndpointConnectionError and
        # ConnectTimeoutError, so this catches both. Skip and keep going.
        print(f"  [{region}] skipped: {type(connection_error).__name__}")
        return 0

    if not repos:
        return 0

    # CodePipeline requires its artifact bucket to live in the pipeline's region,
    # so each region gets its own bucket suffixed with the region name.
    bucket_name = f"{BUCKET_NAME}-{region}"
    print(f"\nRegion {region}: {len(repos)} repo(s) | bucket {bucket_name}")
    ensure_bucket(bucket_name, region)

    for repo in repos:
        repo_name = repo["repositoryName"]
        try:
            default_branch = get_default_branch(repo_name)
            scan_repo(repo_name, default_branch, region, bucket_name, codebuild_role_arn, codepipeline_role_arn)
        except Exception as exception:
            print(f"    Error [{repo_name}]: {exception}")

    return len(repos)


def main():
    # IAM is global, so the service roles are created once and reused across regions.
    codebuild_role_arn = ensure_codebuild_role(CODEBUILD_ROLE_NAME)
    codepipeline_role_arn = ensure_codepipeline_role(CODEPIPELINE_ROLE_NAME)
    print(f"CodeBuild role:    {codebuild_role_arn}")
    print(f"CodePipeline role: {codepipeline_role_arn}")

    regions = get_codecommit_regions()
    print(f"\nProbing {len(regions)} CodeCommit region(s) for repositories...")

    total_repos = 0
    for region in regions:
        total_repos += scan_region(region, codebuild_role_arn, codepipeline_role_arn)

    print(f"\nDone. Scanned {total_repos} repo(s) across all regions.")


if __name__ == "__main__":
    main()
