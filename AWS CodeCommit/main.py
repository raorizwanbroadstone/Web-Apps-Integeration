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


# Merge helpers

def _merge_aibom(reports):
    """Merges multiple CycloneDX AIBOM reports into one.

    bom-refs are prefixed with the repo name to prevent collisions across repos.
    """
    base = {k: v for k, v in reports[0]["data"].items() if k not in ("components", "dependencies", "vulnerabilities")}
    base["components"] = []
    base["dependencies"] = []
    base["vulnerabilities"] = []

    for entry in reports:
        repo_name = entry["repo"]
        report = entry["data"]

        for component in report.get("components", []):
            component = dict(component)
            if "bom-ref" in component:
                component["bom-ref"] = f"{repo_name}:{component['bom-ref']}"
            base["components"].append(component)

        for dep in report.get("dependencies", []):
            dep = dict(dep)
            if "ref" in dep:
                dep["ref"] = f"{repo_name}:{dep['ref']}"
            base["dependencies"].append(dep)

        for vuln in report.get("vulnerabilities", []):
            vuln = dict(vuln)
            if "id" in vuln:
                vuln["id"] = f"{repo_name}:{vuln['id']}"
            base["vulnerabilities"].append(vuln)

    return base


def _merge_grype(reports):
    base = {k: v for k, v in reports[0]["data"].items() if k != "matches"}
    base["matches"] = []
    for entry in reports:
        base["matches"].extend(entry["data"].get("matches", []))
    return base


def _merge_semgrep(reports):
    base = {k: v for k, v in reports[0]["data"].items() if k not in ("results", "errors")}
    base["results"] = []
    base["errors"] = []
    for entry in reports:
        base["results"].extend(entry["data"].get("results", []))
        base["errors"].extend(entry["data"].get("errors", []))
    return base


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
        return None

    build_id = get_build_id_from_execution(pipeline_name, execution_id)
    if not build_id:
        print(f"    Could not retrieve CodeBuild build ID, skipping fetch")
        return None

    aibom_data = fetch_aibom_report(build_id)
    grype_data = fetch_grype_report(build_id)
    semgrep_data = fetch_semgrep_report(build_id)

    return {"aibom": aibom_data, "grype": grype_data, "semgrep": semgrep_data}


def main():
    print(f"Region : {AWS_REGION}")
    print(f"Bucket : {BUCKET_NAME}")

    ensure_bucket(BUCKET_NAME)
    codebuild_role_arn = ensure_codebuild_role(CODEBUILD_ROLE_NAME)
    codepipeline_role_arn = ensure_codepipeline_role(CODEPIPELINE_ROLE_NAME)
    print(f"  CodeBuild role   : {codebuild_role_arn}")
    print(f"  CodePipeline role: {codepipeline_role_arn}")

    repos = get_repos()
    print(f"\nFound {len(repos)} repo(s) in CodeCommit ({AWS_REGION})")

    aibom_reports = []
    grype_reports = []
    semgrep_reports = []

    for repo in repos:
        repo_name = repo["repositoryName"]
        try:
            default_branch = get_default_branch(repo_name)
            result = scan_repo(repo_name, default_branch, codebuild_role_arn, codepipeline_role_arn)
            if result:
                if result["aibom"]:
                    aibom_reports.append({"repo": repo_name, "data": result["aibom"]})
                if result["grype"]:
                    grype_reports.append({"repo": repo_name, "data": result["grype"]})
                if result["semgrep"]:
                    semgrep_reports.append({"repo": repo_name, "data": result["semgrep"]})
        except Exception as error:
            print(f"    ERROR [{repo_name}]: {error}")

    if not any([aibom_reports, grype_reports, semgrep_reports]):
        print("\nNo reports collected.")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    if aibom_reports:
        merged_aibom = _merge_aibom(aibom_reports)
        aibom_path = save_json(merged_aibom, REPORT_DIR, f"aibom_aws_{AWS_REGION}_{timestamp}.json")
        print(f"\nAIBOM   : {aibom_path}")

    if grype_reports:
        merged_grype = _merge_grype(grype_reports)
        grype_path = save_json(merged_grype, SBOM_DIR, f"grype_aws_{AWS_REGION}_{timestamp}.json")
        print(f"SBOM    : {grype_path}")

    if semgrep_reports:
        merged_semgrep = _merge_semgrep(semgrep_reports)
        semgrep_path = save_json(merged_semgrep, SBOM_DIR, f"semgrep_aws_{AWS_REGION}_{timestamp}.json")
        print(f"Semgrep : {semgrep_path}")


if __name__ == "__main__":
    main()
