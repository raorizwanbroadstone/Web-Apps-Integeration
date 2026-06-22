from datetime import datetime, timezone
from codecommit import (
    get_repos,
    get_default_branch,
    ensure_bucket,
    ensure_codebuild_role,
    ensure_codepipeline_role,
    push_buildspec,
    create_codebuild_project,
    create_or_get_pipeline,
    start_pipeline_execution,
    poll_pipeline_completion,
    get_build_id_from_execution,
    fetch_aibom_report,
    fetch_grype_report,
    fetch_semgrep_report,
    save_json,
)
from constants import AWS_REGION, BUCKET_NAME, CODEBUILD_ROLE_NAME, CODEPIPELINE_ROLE_NAME, REPORT_DIR, SBOM_DIR

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


def scan_repo(repo_name, default_branch, codebuild_role_arn, codepipeline_role_arn):
    print(f"\n    Repo: {repo_name}")

    pushed = push_buildspec(repo_name, default_branch, BUILDSPEC_YAML)
    if pushed is None:
        print(f"    Buildspec already up to date, skipping commit")
    else:
        print(f"    Buildspec pushed to {default_branch}")

    create_codebuild_project(repo_name, codebuild_role_arn)
    print(f"    CodeBuild project ready: cytex-scan-{repo_name}")

    pipeline_name = create_or_get_pipeline(repo_name, default_branch, codepipeline_role_arn)
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

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    aibom_data = fetch_aibom_report(build_id)
    if aibom_data:
        aibom_path = save_json(aibom_data, REPORT_DIR, f"aibom_aws_{AWS_REGION}_{repo_name}_{timestamp}.json")
        print(f"    AIBOM:   {aibom_path}")

    grype_data = fetch_grype_report(build_id)
    if grype_data:
        grype_path = save_json(grype_data, SBOM_DIR, f"grype_aws_{AWS_REGION}_{repo_name}_{timestamp}.json")
        print(f"    Grype:   {grype_path}")

    semgrep_data = fetch_semgrep_report(build_id)
    if semgrep_data:
        semgrep_path = save_json(semgrep_data, SBOM_DIR, f"semgrep_aws_{AWS_REGION}_{repo_name}_{timestamp}.json")
        print(f"    Semgrep: {semgrep_path}")


def main():
    print(f"Region: {AWS_REGION}")
    print(f"Bucket: {BUCKET_NAME}")

    ensure_bucket(BUCKET_NAME)
    codebuild_role_arn = ensure_codebuild_role(CODEBUILD_ROLE_NAME)
    codepipeline_role_arn = ensure_codepipeline_role(CODEPIPELINE_ROLE_NAME)
    print(f"  CodeBuild role:    {codebuild_role_arn}")
    print(f"  CodePipeline role: {codepipeline_role_arn}")

    repos = get_repos()
    print(f"\nFound {len(repos)} repo(s) in CodeCommit ({AWS_REGION})")

    for repo in repos:
        repo_name = repo["repositoryName"]
        try:
            default_branch = get_default_branch(repo_name)
            scan_repo(repo_name, default_branch, codebuild_role_arn, codepipeline_role_arn)
        except Exception as exception:
            print(f"    Error [{repo_name}]: {exception}")


if __name__ == "__main__":
    main()
