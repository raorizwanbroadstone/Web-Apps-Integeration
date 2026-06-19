import boto3
import botocore.exceptions
import json
import os
import time
from datetime import datetime, timezone
from constants import AWS_REGION, GROQ_API_KEY, BUCKET_NAME, CODEBUILD_ROLE_NAME, CODEPIPELINE_ROLE_NAME, REPORT_DIR, SBOM_DIR

codecommit_client = boto3.client("codecommit", region_name=AWS_REGION)
codebuild_client = boto3.client("codebuild", region_name=AWS_REGION)
codepipeline_client = boto3.client("codepipeline", region_name=AWS_REGION)
s3_client = boto3.client("s3", region_name=AWS_REGION)
iam_client = boto3.client("iam")


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


def get_repo_clone_url(repo_name):
    repo_metadata = codecommit_client.get_repository(repositoryName=repo_name)["repositoryMetadata"]
    return repo_metadata["cloneUrlHttp"]


# S3 bucket

def ensure_bucket(bucket_name):
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except botocore.exceptions.ClientError as error:
        error_code = error.response["Error"]["Code"]
        if error_code == "404":
            if AWS_REGION == "us-east-1":
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": AWS_REGION},
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

_CODEBUILD_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_CODEBUILD_MANAGED_POLICIES = [
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
            AssumeRolePolicyDocument=_CODEBUILD_TRUST_POLICY,
            Description="Service role for Cytex security scanning CodeBuild projects",
        )
        for policy_arn in _CODEBUILD_MANAGED_POLICIES:
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"  Created IAM role: {role_name} (waiting 10s for propagation)")
        time.sleep(10)
        return role_response["Role"]["Arn"]


# IAM role for CodePipeline

_CODEPIPELINE_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codepipeline.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_CODEPIPELINE_INLINE_POLICY = json.dumps({
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
            AssumeRolePolicyDocument=_CODEPIPELINE_TRUST_POLICY,
            Description="Service role for Cytex security scanning CodePipeline pipelines",
        )
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName="cytex-codepipeline-policy",
            PolicyDocument=_CODEPIPELINE_INLINE_POLICY,
        )
        print(f"  Created IAM role: {role_name} (waiting 10s for propagation)")
        time.sleep(10)
        return role_response["Role"]["Arn"]


# Buildspec injection

def _get_existing_buildspec(repo_name, branch):
    try:
        file_response = codecommit_client.get_file(
            repositoryName=repo_name,
            commitSpecifier=branch,
            filePath="buildspec.yml",
        )
        return file_response["fileContent"].decode("utf-8")
    except botocore.exceptions.ClientError as error:
        not_found_codes = (
            "FileDoesNotExistException",
            "CommitDoesNotExistException",
            "BranchDoesNotExistException",
        )
        if error.response["Error"]["Code"] in not_found_codes:
            return None
        raise


def _get_branch_head_commit(repo_name, branch):
    try:
        branch_response = codecommit_client.get_branch(repositoryName=repo_name, branchName=branch)
        return branch_response["branch"]["commitId"]
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "BranchDoesNotExistException":
            return None
        raise


def push_buildspec(repo_name, branch, yaml_content):
    existing_content = _get_existing_buildspec(repo_name, branch)
    if existing_content is not None and existing_content.strip() == yaml_content.strip():
        return None

    head_commit_id = _get_branch_head_commit(repo_name, branch)

    put_file_kwargs = {
        "repositoryName": repo_name,
        "branchName": branch,
        "fileContent": yaml_content.encode("utf-8"),
        "filePath": "buildspec.yml",
        "commitMessage": "Add security scanning buildspec [skip ci]",
    }
    if head_commit_id:
        put_file_kwargs["parentCommitId"] = head_commit_id

    return codecommit_client.put_file(**put_file_kwargs)


# CodeBuild project

def _find_codebuild_project(project_name):
    batch_response = codebuild_client.batch_get_projects(names=[project_name])
    projects = batch_response.get("projects", [])
    return projects[0] if projects else None


def create_codebuild_project(repo_name, role_arn, bucket_name=BUCKET_NAME):
    project_name = f"cytex-scan-{repo_name}"
    existing_project = _find_codebuild_project(project_name)

    if existing_project:
        # Update source type if project was created before CodePipeline was added
        if existing_project.get("source", {}).get("type") != "CODEPIPELINE":
            codebuild_client.update_project(
                name=project_name,
                source={"type": "CODEPIPELINE"},
                artifacts={"type": "CODEPIPELINE"},
            )
        return existing_project

    create_response = codebuild_client.create_project(
        name=project_name,
        source={"type": "CODEPIPELINE"},
        artifacts={"type": "CODEPIPELINE"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_MEDIUM",
            "environmentVariables": [
                {"name": "GROQ_API_KEY", "value": GROQ_API_KEY, "type": "PLAINTEXT"},
                {"name": "BUCKET_NAME", "value": bucket_name, "type": "PLAINTEXT"},
            ],
            "privilegedMode": False,
        },
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

def create_or_get_pipeline(repo_name, branch, pipeline_role_arn, artifact_bucket=BUCKET_NAME):
    pipeline_name = f"cytex-scan-{repo_name}"

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
                            "ProjectName": f"cytex-scan-{repo_name}",
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


def poll_pipeline_completion(pipeline_name, execution_id, interval=15, timeout=1800):
    elapsed = 0
    while elapsed < timeout:
        try:
            response = codepipeline_client.get_pipeline_execution(
                pipelineName=pipeline_name,
                pipelineExecutionId=execution_id,
            )
        except botocore.exceptions.ClientError as error:
            # Execution may not be registered immediately after start_pipeline_execution
            if error.response["Error"]["Code"] == "PipelineExecutionNotFoundException" and elapsed < 60:
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

def _build_id_to_s3_prefix(build_id):
    # CodeBuild build IDs look like 'project-name:uuid'; buildspec uses tr ':' '/'
    return build_id.replace(":", "/")


def _download_s3_json(bucket_name, s3_key):
    try:
        s3_response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
        return json.loads(s3_response["Body"].read().decode("utf-8"))
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise


def _save_json(data, directory, filename):
    os.makedirs(directory, exist_ok=True)
    file_path = os.path.join(directory, filename)
    with open(file_path, "w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2)
    return file_path


def download_aibom_report(build_id, region, repo_name, bucket_name=BUCKET_NAME):
    s3_key = f"{_build_id_to_s3_prefix(build_id)}/aibom-report.cdx.json"
    report_data = _download_s3_json(bucket_name, s3_key)
    if report_data is None:
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return _save_json(report_data, REPORT_DIR, f"aibom_aws_{region}_{repo_name}_{timestamp}.json")


def download_grype_report(build_id, region, repo_name, bucket_name=BUCKET_NAME):
    s3_key = f"{_build_id_to_s3_prefix(build_id)}/grype-report.json"
    report_data = _download_s3_json(bucket_name, s3_key)
    if report_data is None:
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return _save_json(report_data, SBOM_DIR, f"grype_aws_{region}_{repo_name}_{timestamp}.json")


def download_semgrep_report(build_id, region, repo_name, bucket_name=BUCKET_NAME):
    s3_key = f"{_build_id_to_s3_prefix(build_id)}/semgrep-report.json"
    report_data = _download_s3_json(bucket_name, s3_key)
    if report_data is None:
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return _save_json(report_data, SBOM_DIR, f"semgrep_aws_{region}_{repo_name}_{timestamp}.json")
