from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from app.utils.logging import get_logger

log = get_logger(__name__)


def get_attack_mapping(cve_id: str) -> str:
    """CVE ID로 MITRE ATT&CK / CAPEC / CWE 매핑 조회 (sync)."""
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(f"https://cve.circl.lu/api/cve/{cve_id}")

        if response.status_code != 200:
            return "Unknown"

        cve_data = response.json()

        capec_entries = cve_data.get("capec", [])
        if capec_entries:
            return ", ".join(entry.get("name", "Unknown") for entry in capec_entries)

        cwe_list = cve_data.get("problemtype", {}).get("problemtype_data", [])
        if cwe_list:
            cwe_entries = cwe_list[0].get("description", [])
            if cwe_entries:
                return ", ".join(entry.get("value", "Unknown CWE") for entry in cwe_entries)

        problem_types = cve_data.get("containers", {}).get("cna", {}).get("problemTypes", [])
        if problem_types:
            descriptions = problem_types[0].get("descriptions", [])
            if descriptions:
                return descriptions[0].get("description", "No CAPEC or CWE Data Available")

        return "Unknown"
    except Exception as e:
        log.error("mitre_mapping_failed", cve_id=cve_id, error=str(e))
        return "Unknown"


def enrich_vulnerabilities_with_mitre(vulnerabilities: list[dict]) -> list[dict]:
    """취약점 목록에 MITRE ATT&CK 매핑을 병렬로 추가."""
    cve_ids = list({v["cve_id"] for v in vulnerabilities if v.get("cve_id", "N/A") != "N/A"})
    if not cve_ids:
        return vulnerabilities

    mapping: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(get_attack_mapping, cve_id): cve_id for cve_id in cve_ids}
        for future in as_completed(futures):
            cve_id = futures[future]
            mapping[cve_id] = future.result()

    for vuln in vulnerabilities:
        vuln["mitre_attack"] = mapping.get(vuln.get("cve_id"), "Unknown")

    log.info("mitre_enrichment_complete", total_cves=len(cve_ids))
    return vulnerabilities
