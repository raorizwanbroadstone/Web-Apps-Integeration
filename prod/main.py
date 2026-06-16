from azure import (
    get_latest_build,
    download_aibom_report,
    download_grype_report
)
from constants import ORG, PROJECT


def main():
    build = get_latest_build()

    if not build:
        raise Exception("No builds found")

    build_id = build["id"]

    repo_name = build.get("repository", {}).get("name", "repo")

    print("Build:", build_id)

    aibom_path = download_aibom_report(
        build_id,
        ORG,
        PROJECT,
        repo_name
    )

    grype_path = download_grype_report(
        build_id,
        ORG,
        PROJECT,
        repo_name
    )

    print("AIBOM:", aibom_path)
    print("SBOM :", grype_path)


if __name__ == "__main__":
    main()