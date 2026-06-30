from datetime import datetime, timezone
from azure import (
    get_projects,
    get_repos,
    push_pipeline_yaml,
    create_pipeline,
    queue_pipeline_run,
    poll_build_completion,
    download_aibom_report,
    download_grype_report,
    download_semgrep_report,
)
from constants import ORG

PIPELINE_YAML = """\
trigger:
- main

pool:
  vmImage: ubuntu-latest

steps:
- checkout: self

- script: |
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  displayName: Install Grype

- script: |
    python3 -m pip install --upgrade pip
    python3 -m pip install semgrep
  displayName: Install Semgrep

- script: |
    python3 -m pip install --pre "cisco-aibom[agentic]==1.0.0rc2" langchain-groq
  displayName: Install Cisco AIBOM

- script: |
    if [ -z "$GROQ_API_KEY" ]; then
      echo "GROQ_API_KEY is missing"
      exit 1
    fi

    echo "GROQ_API_KEY is available"
    echo "GROQ_API_KEY length: ${#GROQ_API_KEY}"
  displayName: Verify Groq API Key
  env:
    GROQ_API_KEY: $(GROQ_API_KEY)

- script: |
    mkdir -p ~/.aibom/catalogs

    curl -L \\
      -o ~/.aibom/catalogs/aibom_catalog-1.0.0rc2.duckdb \\
      https://github.com/cisco-ai-defense/aibom/releases/download/1.0.0rc2/aibom_catalog-1.0.0rc2.duckdb
  displayName: Download Cisco Catalog

- script: |
    grype dir:. -o json > grype-report.json
  displayName: Run Grype

- script: |
    semgrep --config=auto . --json > semgrep-report.json
  displayName: Run Semgrep

- script: |
    cisco-aibom analyze . \\
      -o cyclonedx \\
      -O aibom-report.cdx.json \\
      --llm-model llama-3.3-70b-versatile \\
      --llm-provider groq \\
      --llm-api-key "$GROQ_API_KEY"
  displayName: Run Cisco AIBOM
  env:
    GROQ_API_KEY: $(GROQ_API_KEY)

- task: PublishPipelineArtifact@1
  inputs:
    targetPath: grype-report.json
    artifact: grype-report

- task: PublishPipelineArtifact@1
  inputs:
    targetPath: semgrep-report.json
    artifact: semgrep-report

- task: PublishPipelineArtifact@1
  inputs:
    targetPath: aibom-report.cdx.json
    artifact: aibom-report
"""


def scan_repo(project_name, repo):
    repo_id = repo["id"]
    repo_name = repo["name"]
    default_branch = repo.get("defaultBranch", "refs/heads/main")

    print(f"\n    Repo: {repo_name}")

    pushed = push_pipeline_yaml(project_name, repo_id, default_branch, PIPELINE_YAML)
    if pushed is None:
        print(f"    YAML already up to date, skipping commit")
    else:
        print(f"    YAML pushed to {default_branch.replace('refs/heads/', '')}")

    pipeline = create_pipeline(project_name, repo_id, repo_name)
    pipeline_id = pipeline["id"]
    print(f"    Pipeline ready: {pipeline_id}")

    run = queue_pipeline_run(project_name, pipeline_id)
    run_id = run["id"]
    print(f"    Run queued: {run_id}")

    completed_run = poll_build_completion(project_name, pipeline_id, run_id)
    build_result = completed_run.get("result", "unknown")
    print(f"    Build completed: {build_result}")

    if build_result != "succeeded":
        print(f"    Skipping artifact download (build {build_result})")
        return

    # One timestamp shared by all three reports so they sort together for the repo.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    aibom_path = download_aibom_report(run_id, ORG, project_name, repo_name, timestamp)
    if aibom_path:
        print(f"    AIBOM:   {aibom_path}")

    grype_path = download_grype_report(run_id, ORG, project_name, repo_name, timestamp)
    if grype_path:
        print(f"    Grype:   {grype_path}")

    semgrep_path = download_semgrep_report(run_id, ORG, project_name, repo_name, timestamp)
    if semgrep_path:
        print(f"    Semgrep: {semgrep_path}")


def main():
    projects = get_projects()
    print(f"Found {len(projects)} project(s)")

    for project in projects:
        project_name = project["name"]
        print(f"\nProject: {project_name}")

        repos = get_repos(project_name)
        print(f"  Found {len(repos)} repo(s)")

        for repo in repos:
            try:
                scan_repo(project_name, repo)
            except Exception as exception:
                print(f"    Error [{repo['name']}]: {exception}")


if __name__ == "__main__":
    main()
