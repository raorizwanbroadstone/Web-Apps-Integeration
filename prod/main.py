from azure import get_latest_build, download_aibom_report
from constants import ORG, PROJECT


def main():
    build = get_latest_build()

    if not build:
        raise Exception("No builds found")

    build_id = build["id"]

    print(f"Build ID: {build_id}")

    repo_name = build.get("repository", {}).get("name", "repo")

    file_path = download_aibom_report(
        build_id,
        ORG,
        PROJECT,
        repo_name
    )

    if not file_path:
        raise Exception("AIBOM not found")

    print(f"Saved: {file_path}")


if __name__ == "__main__":
    main()