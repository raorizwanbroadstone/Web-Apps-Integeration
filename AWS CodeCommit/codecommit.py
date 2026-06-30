import boto3
import botocore.exceptions
import json
import os
import time
from botocore.config import Config
from constants import (
    GROQ_API_KEY,
    CODEBUILD_ROLE_NAME,
    CODEPIPELINE_ROLE_NAME,
    REPORT_DIR,
    SBOM_DIR,
    RESOURCE_PREFIX,
    COMMIT_MESSAGE,
)


def scan_resource_name(repo_name):
    """The shared name used for the per-repo CodeBuild project and CodePipeline pipeline.

    Built from RESOURCE_PREFIX so the `cytex-scan-<repo>` convention lives in a single place.
    """
    return f"{RESOURCE_PREFIX}-{repo_name}"

CLIENT_CONFIG = Config(
    connect_timeout=10,
    read_timeout=60,
    retries={"max_attempts": 3, "mode": "adaptive"},
)

# IAM is a global service, so its client is region-independent and built once.
iam_client = boto3.client("iam", config=CLIENT_CONFIG)

# The remaining services are regional. Rather than locking to a single region from
# .env, the clients are (re)built per region by configure_region() as main.py walks
# every region the account uses. They start as None and must be configured before use.
codecommit_client = None
codebuild_client = None
codepipeline_client = None
s3_client = None


def configure_region(region):
    """Point all regional clients at the given region. Call before scanning that region."""
    global codecommit_client, codebuild_client, codepipeline_client, s3_client
    codecommit_client = boto3.client("codecommit", region_name=region, config=CLIENT_CONFIG)
    codebuild_client = boto3.client("codebuild", region_name=region, config=CLIENT_CONFIG)
    codepipeline_client = boto3.client("codepipeline", region_name=region, config=CLIENT_CONFIG)
    s3_client = boto3.client("s3", region_name=region, config=CLIENT_CONFIG)


def get_codecommit_regions():
    """Returns the regions worth scanning: those that support CodeCommit and, where we
    are allowed to find out, only the ones actually enabled for this account.
    """
    codecommit_supported = set(boto3.session.Session().get_available_regions("codecommit"))

    ec2_client = boto3.client("ec2", region_name="us-east-1", config=CLIENT_CONFIG)
    try:
        enabled_regions = [region["RegionName"] for region in ec2_client.describe_regions()["Regions"]]
    except botocore.exceptions.ClientError as client_error:
        if client_error.response["Error"]["Code"] in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            print("  (ec2:DescribeRegions not permitted -- probing all CodeCommit regions; "
                  "grant it for a faster sweep)")
            return sorted(codecommit_supported)
        raise

    return [region for region in enabled_regions if region in codecommit_supported]


# Discovery

def get_repos():
    repos = []
    paginator = codecommit_client.get_paginator("list_repositories")
    for page in paginator.paginate(sortBy="repositoryName", order="ascending"):
        repos.extend(page.get("repositories", []))
    return repos


def get_default_branch(repo_name):
    repo_metadata = codecommit_client.get_repository(repositoryName=repo_name)["repositoryMetadata"]
    return repo_metadata.get("defaultBranch", "main")


# S3 bucket

def ensure_bucket(bucket_name, region):
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except botocore.exceptions.ClientError as client_error:
        error_code = client_error.response["Error"]["Code"]
        if error_code == "404":
            # us-east-1 rejects a LocationConstraint; every other region requires it.
            if region == "us-east-1":
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": region},
                )
            print(f"  Created S3 bucket: {bucket_name}")
        elif error_code == "403":
            raise RuntimeError(
                f"S3 bucket '{bucket_name}' exists but belongs to a different AWS account. "
                f"Set AWS_S3_BUCKET in your .env to a unique name."
            )
        else:
            raise

    # CodePipeline requires versioning on the artifact bucket
    s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )


# IAM role for CodeBuild

CODEBUILD_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

CODEBUILD_MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/AWSCodeCommitReadOnly",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
]


def ensure_codebuild_role(role_name=CODEBUILD_ROLE_NAME):
    try:
        return iam_client.get_role(RoleName=role_name)["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=CODEBUILD_TRUST_POLICY,
            Description="Service role for Cytex security scanning CodeBuild projects",
        )
        for policy_arn in CODEBUILD_MANAGED_POLICIES:
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"  Created IAM role: {role_name} (waiting 10s for propagation)")
        time.sleep(10)
        return role_response["Role"]["Arn"]


# IAM role for CodePipeline

CODEPIPELINE_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codepipeline.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

CODEPIPELINE_INLINE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "codecommit:GetBranch",
                "codecommit:GetCommit",
                "codecommit:UploadArchive",
                "codecommit:GetUploadArchiveStatus",
                "codecommit:CancelUploadArchive",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "codebuild:BatchGetBuilds",
                "codebuild:StartBuild",
                "codebuild:StopBuild",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:PutObject",
                "s3:GetBucketVersioning",
                "s3:GetBucketAcl",
                "s3:GetBucketLocation",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
        },
    ],
})


def ensure_codepipeline_role(role_name=CODEPIPELINE_ROLE_NAME):
    try:
        return iam_client.get_role(RoleName=role_name)["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=CODEPIPELINE_TRUST_POLICY,
            Description="Service role for Cytex security scanning CodePipeline pipelines",
        )
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName="cytex-codepipeline-policy",
            PolicyDocument=CODEPIPELINE_INLINE_POLICY,
        )
        print(f"  Created IAM role: {role_name} (waiting 10s for propagation)")
        time.sleep(10)
        return role_response["Role"]["Arn"]


# Pipeline YAML injection

def get_existing_buildspec(repo_name, branch):
    """Returns the current content of cytex.yml, or None if the file does not exist."""
    try:
        file_response = codecommit_client.get_file(
            repositoryName=repo_name,
            commitSpecifier=branch,
            filePath="cytex.yml",
        )
        return file_response["fileContent"].decode("utf-8")
    except botocore.exceptions.ClientError as client_error:
        not_found_codes = (
            "FileDoesNotExistException",
            "CommitDoesNotExistException",
            "BranchDoesNotExistException",
        )
        if client_error.response["Error"]["Code"] in not_found_codes:
            return None
        raise


def get_branch_head_commit(repo_name, branch):
    """Returns the current HEAD commit ID for the branch, or None if the branch does not exist."""
    try:
        branch_response = codecommit_client.get_branch(repositoryName=repo_name, branchName=branch)
        return branch_response["branch"]["commitId"]
    except botocore.exceptions.ClientError as client_error:
        if client_error.response["Error"]["Code"] == "BranchDoesNotExistException":
            return None
        raise


def push_buildspec(repo_name, branch, yaml_content):
    """Commits cytex.yml to the repository branch.

    Returns None if the file already exists with identical content, skipping the commit.
    """
    existing_content = get_existing_buildspec(repo_name, branch)
    if existing_content is not None and existing_content.strip() == yaml_content.strip():
        return None

    head_commit_id = get_branch_head_commit(repo_name, branch)

    put_file_kwargs = {
        "repositoryName": repo_name,
        "branchName": branch,
        "fileContent": yaml_content.encode("utf-8"),
        "filePath": "cytex.yml",
        "commitMessage": COMMIT_MESSAGE,
    }
    if head_commit_id:
        put_file_kwargs["parentCommitId"] = head_commit_id

    return codecommit_client.put_file(**put_file_kwargs)


# CodeBuild project

def find_codebuild_project(project_name):
    """Returns the existing CodeBuild project dict if found, else None."""
    batch_response = codebuild_client.batch_get_projects(names=[project_name])
    projects = batch_response.get("projects", [])
    return projects[0] if projects else None


def build_environment_config(environment_variables):
    """Wraps the env-var list in the full CodeBuild environment block."""
    return {
        "type": "LINUX_CONTAINER",
        "image": "aws/codebuild/standard:7.0",
        "computeType": "BUILD_GENERAL1_MEDIUM",
        "environmentVariables": environment_variables,
        "privilegedMode": False,
    }


def build_environment_variables(bucket_name):
    """The env vars the buildspec needs: the per-region report bucket and the Groq key for AIBOM."""
    return [
        {"name": "BUCKET_NAME", "value": bucket_name, "type": "PLAINTEXT"},
        {"name": "GROQ_API_KEY", "value": GROQ_API_KEY, "type": "PLAINTEXT"},
    ]


def create_codebuild_project(repo_name, role_arn, bucket_name):
    project_name = scan_resource_name(repo_name)
    existing_project = find_codebuild_project(project_name)
    if existing_project:
        # Refresh only our managed vars (bucket + Groq key); leave any others intact.
        existing_env = existing_project.get("environment", {}).get("environmentVariables", [])
        environment_variables = [var for var in existing_env if var["name"] not in {"BUCKET_NAME", "GROQ_API_KEY"}]
        environment_variables.extend(build_environment_variables(bucket_name))

        codebuild_client.update_project(
            name=project_name,
            source={"type": "CODEPIPELINE", "buildspec": "cytex.yml"},
            artifacts={"type": "CODEPIPELINE"},
            environment=build_environment_config(environment_variables),
        )
        return existing_project

    create_response = codebuild_client.create_project(
        name=project_name,
        source={"type": "CODEPIPELINE", "buildspec": "cytex.yml"},
        artifacts={"type": "CODEPIPELINE"},
        environment=build_environment_config(build_environment_variables(bucket_name)),
        serviceRole=role_arn,
        timeoutInMinutes=30,
        logsConfig={
            "cloudWatchLogs": {
                "status": "ENABLED",
                "groupName": "/aws/codebuild/cytex-scan",
                "streamName": repo_name,
            }
        },
    )
    return create_response.get("project", {})


# CodePipeline

def create_or_get_pipeline(repo_name, branch, pipeline_role_arn, artifact_bucket):
    pipeline_name = scan_resource_name(repo_name)

    try:
        codepipeline_client.get_pipeline(name=pipeline_name)
        return pipeline_name
    except codepipeline_client.exceptions.PipelineNotFoundException:
        pass

    codepipeline_client.create_pipeline(
        pipeline={
            "name": pipeline_name,
            "roleArn": pipeline_role_arn,
            "artifactStore": {
                "type": "S3",
                "location": artifact_bucket,
            },
            "stages": [
                {
                    "name": "Source",
                    "actions": [{
                        "name": "CodeCommitSource",
                        "actionTypeId": {
                            "category": "Source",
                            "owner": "AWS",
                            "provider": "CodeCommit",
                            "version": "1",
                        },
                        "configuration": {
                            "RepositoryName": repo_name,
                            "BranchName": branch,
                            "PollForSourceChanges": "true",
                        },
                        "outputArtifacts": [{"name": "SourceArtifact"}],
                    }],
                },
                {
                    "name": "Build",
                    "actions": [{
                        "name": "SecurityScan",
                        "actionTypeId": {
                            "category": "Build",
                            "owner": "AWS",
                            "provider": "CodeBuild",
                            "version": "1",
                        },
                        "configuration": {
                            "ProjectName": scan_resource_name(repo_name),
                        },
                        "inputArtifacts": [{"name": "SourceArtifact"}],
                        "outputArtifacts": [{"name": "BuildArtifact"}],
                    }],
                },
            ],
        }
    )
    return pipeline_name


def start_pipeline_execution(pipeline_name):
    response = codepipeline_client.start_pipeline_execution(name=pipeline_name)
    return response["pipelineExecutionId"]


def poll_pipeline_completion(pipeline_name, execution_id, initial_delay=300, interval=60, timeout=1800):
    # Wait initial_delay before the first status check, then poll every `interval` seconds.
    print(f"    Waiting {initial_delay}s before first status check...")
    time.sleep(initial_delay)
    elapsed = initial_delay

    while elapsed < timeout:
        try:
            response = codepipeline_client.get_pipeline_execution(
                pipelineName=pipeline_name,
                pipelineExecutionId=execution_id,
            )
        except botocore.exceptions.ClientError as client_error:
            # Execution may not be registered immediately after start_pipeline_execution
            if (client_error.response["Error"]["Code"] == "PipelineExecutionNotFoundException"
                    and elapsed < initial_delay + 60):
                print(f"    [{elapsed}s] waiting for execution to register...")
                time.sleep(interval)
                elapsed += interval
                continue
            raise

        pipeline_status = response["pipelineExecution"]["status"]
        if pipeline_status not in ("InProgress", "Stopping"):
            return pipeline_status
        print(f"    [{elapsed}s] pipeline {pipeline_name} -> {pipeline_status}")
        time.sleep(interval)
        elapsed += interval
    raise TimeoutError(f"Pipeline {pipeline_name} execution {execution_id} did not complete within {timeout}s")


def get_build_id_from_execution(pipeline_name, execution_id):
    response = codepipeline_client.list_action_executions(
        pipelineName=pipeline_name,
        filter={"pipelineExecutionId": execution_id},
    )
    for action_detail in response.get("actionExecutionDetails", []):
        if action_detail.get("stageName") == "Build" and action_detail.get("actionName") == "SecurityScan":
            execution_result = action_detail.get("output", {}).get("executionResult", {})
            return execution_result.get("externalExecutionId")
    return None


# S3 artifact download

def build_id_to_s3_prefix(build_id):
    # CodeBuild build IDs look like 'project-name:uuid'; the buildspec converts ':' to '/' for the S3 path
    return build_id.replace(":", "/")


def download_s3_json(bucket_name, s3_key):
    try:
        s3_response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
        return json.loads(s3_response["Body"].read().decode("utf-8"))
    except botocore.exceptions.ClientError as client_error:
        if client_error.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise


def save_json_file(data, directory, filename):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2)
    return path


def download_report(build_id, bucket_name, artifact_filename):
    """Reads a single report artifact from S3, or None if the build never produced it."""
    s3_key = f"{build_id_to_s3_prefix(build_id)}/{artifact_filename}"
    return download_s3_json(bucket_name, s3_key)


# Each download_* function fetches one report and saves it locally, returning the saved path
# (or None if the artifact is missing). The timestamp is passed in by the caller so all three
# reports for a single repo share one timestamp instead of drifting between calls.

def download_aibom_report(build_id, bucket_name, region, repo_name, timestamp):
    data = download_report(build_id, bucket_name, "aibom-report.cdx.json")
    if data is None:
        return None
    return save_json_file(data, REPORT_DIR, f"aibom_aws_{region}_{repo_name}_{timestamp}.json")


def download_grype_report(build_id, bucket_name, region, repo_name, timestamp):
    data = download_report(build_id, bucket_name, "grype-report.json")
    if data is None:
        return None
    return save_json_file(data, SBOM_DIR, f"grype_aws_{region}_{repo_name}_{timestamp}.json")


def download_semgrep_report(build_id, bucket_name, region, repo_name, timestamp):
    data = download_report(build_id, bucket_name, "semgrep-report.json")
    if data is None:
        return None
    return save_json_file(data, SBOM_DIR, f"semgrep_aws_{region}_{repo_name}_{timestamp}.json")
