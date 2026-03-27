import httpx
from app.utils.logging import get_logger

log = get_logger(__name__)


async def get_attack_mapping(cve_id: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://cve.circl.lu/api/cve/{cve_id}")

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
