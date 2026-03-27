import json
import os
import subprocess
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


def generate_sbom(target_path: str, output_dir: str) -> tuple[str, dict]:
    sbom_file = os.path.join(output_dir, "sbom.json")
    cmd = [settings.SYFT_PATH, f"dir:{target_path}", "-o", "spdx-json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        log.error("sbom_generation_failed", error=result.stderr)
        raise Exception(f"SBOM generation failed: {result.stderr}")

    sbom_data = json.loads(result.stdout)
    with open(sbom_file, "w", encoding="utf-8") as f:
        json.dump(sbom_data, f, indent=4)

    log.info("sbom_generated", path=sbom_file, package_count=len(sbom_data.get("packages", [])))
    return sbom_file, sbom_data


def generate_sbom_for_package(package_path: str) -> dict:
    sbom_file = os.path.join(package_path, "sbom.json")
    cmd = [settings.SYFT_PATH, "packages", package_path, "-o", "spdx-json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        raise Exception("SBOM generation failed")

    sbom_data = json.loads(result.stdout)
    with open(sbom_file, "w", encoding="utf-8") as f:
        json.dump(sbom_data, f, indent=4)

    return {"sbom_path": sbom_file, "sbom_data": sbom_data}


def get_sbom_packages(sbom_data: dict) -> list[dict]:
    packages = []
    for pkg in sbom_data.get("packages", []):
        download_link = "N/A"
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                download_link = ref.get("referenceLocator", "N/A")
                break
            elif ref.get("referenceType") == "cpe23Type" and download_link == "N/A":
                download_link = ref.get("referenceLocator", "N/A")

        packages.append({
            "package_name": pkg.get("name", "N/A"),
            "version": pkg.get("versionInfo", "N/A"),
            "license": pkg.get("licenseConcluded", "Unknown"),
            "download_link": download_link,
        })
    return packages


def get_missing_sbom_packages(sbom_data: dict, requirements_path: str) -> list[str]:
    sbom_packages = {
        pkg.get("name", "").lower(): pkg.get("versionInfo", "N/A")
        for pkg in sbom_data.get("packages", [])
    }
    missing = []
    if os.path.exists(requirements_path):
        with open(requirements_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    dep_name = line.split("==")[0]
                    if dep_name not in sbom_packages:
                        missing.append(line)
    return missing
