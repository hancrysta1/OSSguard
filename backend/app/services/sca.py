import json
import os
import subprocess
from app.config import settings
from app.utils.logging import get_logger
from app.services.sbom import get_missing_sbom_packages

log = get_logger(__name__)


def analyze_sca(sbom_file: str, output_dir: str) -> tuple[str, dict]:
    sca_output_file = os.path.join(output_dir, "sca_output.json")
    cmd = [settings.TRIVY_PATH, "sbom", sbom_file, "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        log.error("sca_analysis_failed", error=result.stderr)
        return sca_output_file, {"Results": []}

    sca_data = json.loads(result.stdout)
    with open(sca_output_file, "w", encoding="utf-8") as f:
        json.dump(sca_data, f, indent=4)

    log.info("sca_analysis_complete", file=sca_output_file)
    return sca_output_file, sca_data


def analyze_sca_for_package(sbom_file: str) -> dict:
    cmd = [settings.TRIVY_PATH, "sbom", sbom_file, "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        raise Exception(f"SCA analysis failed: {result.stderr}")

    sca_data = json.loads(result.stdout)
    vuln_count = sum(len(r.get("Vulnerabilities", [])) for r in sca_data.get("Results", []))
    sca_data["total_vulnerabilities"] = vuln_count
    return sca_data


def get_top_vulnerabilities(sca_data: dict) -> list[dict]:
    vulnerabilities = []
    for result in sca_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulnerabilities.append({
                "cve_id": vuln.get("VulnerabilityID", "N/A"),
                "package": vuln.get("PkgName", "N/A"),
                "description": vuln.get("Description", "No description available"),
                "fix_version": vuln.get("FixedVersion", "No fix available"),
                "severity": vuln.get("Severity", "UNKNOWN"),
            })
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)
    return vulnerabilities[:3]


def get_vulnerability_analysis(sca_data: dict) -> list[dict]:
    vulnerabilities = []
    for result in sca_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulnerabilities.append({
                "cve_id": vuln.get("VulnerabilityID", "N/A"),
                "package": vuln.get("PkgName", "N/A"),
                "installed_version": vuln.get("InstalledVersion", "N/A"),
                "fixed_version": vuln.get("FixedVersion", "No fix available"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "cwe": vuln.get("PrimaryAttackVector", "N/A"),
            })
    return vulnerabilities


def get_update_recommendations(sca_data: dict) -> dict:
    updates = {}
    for result in sca_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            pkg_name = vuln.get("PkgName", "N/A")
            if pkg_name not in updates:
                updates[pkg_name] = {
                    "installed_version": vuln.get("InstalledVersion", "N/A"),
                    "recommended_versions": set(),
                    "severities": set(),
                    "cve_list": set(),
                }
            updates[pkg_name]["recommended_versions"].add(vuln.get("FixedVersion", "No fix available"))
            updates[pkg_name]["severities"].add(vuln.get("Severity", "UNKNOWN"))
            updates[pkg_name]["cve_list"].add(vuln.get("VulnerabilityID", "N/A"))

    for pkg in updates:
        updates[pkg]["recommended_versions"] = list(updates[pkg]["recommended_versions"])
        updates[pkg]["severities"] = list(updates[pkg]["severities"])
        updates[pkg]["cve_list"] = list(updates[pkg]["cve_list"])
    return updates


def summarize_security_analysis(sca_data: dict, sbom_data: dict, requirements_path: str) -> dict:
    total_vulnerabilities = 0
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    missing_packages = get_missing_sbom_packages(sbom_data, requirements_path)
    recommended_updates = {}
    affected_packages = set()

    for result in sca_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN").upper()
            if severity in severity_count:
                severity_count[severity] += 1
            total_vulnerabilities += 1
            recommended_updates[vuln.get("PkgName", "")] = vuln.get("FixedVersion", "N/A")
            affected_packages.add(vuln.get("PkgName", ""))

    return {
        "total_vulnerabilities": total_vulnerabilities,
        "severity_count": severity_count,
        "missing_packages_count": len(missing_packages),
        "recommended_updates_count": len(recommended_updates),
        "affected_packages_count": len(affected_packages),
    }
