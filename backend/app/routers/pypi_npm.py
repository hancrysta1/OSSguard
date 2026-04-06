import json
import os
from fastapi import APIRouter, HTTPException
from app.schemas.pypi_npm import PackageRequest
from app.utils.redis_client import redis_client
from app.utils.logging import get_logger
from app.workers.tasks import install_package_task, package_analysis_task

log = get_logger(__name__)
router = APIRouter(prefix="/pypi-npm", tags=["pypi-npm"])


@router.post("/install_package")
async def api_install_package(req: PackageRequest):
    task = install_package_task.delay(req.package_manager, req.package_name, req.package_version)
    return {"task_id": task.id, "message": "Package installation started"}


@router.post("/store_analysis")
async def api_store_analysis(req: PackageRequest):
    task = package_analysis_task.delay(req.package_manager, req.package_name, req.package_version)
    return {"task_id": task.id, "message": "Package analysis started"}


@router.get("/install-status/{task_id}")
async def get_install_status(task_id: str):
    task = install_package_task.AsyncResult(task_id)
    return {"task_id": task_id, "status": task.status, "result": task.result}


@router.get("/store-status/{task_id}")
async def get_store_status(task_id: str):
    task = package_analysis_task.AsyncResult(task_id)
    return {"task_id": task_id, "status": task.status, "result": task.info}


@router.get("/dashboard/{package_name}")
async def get_dashboard(package_name: str):
    """PyPI/npm 분석 결과를 GitHub g_dashboard와 동일한 구조로 반환."""
    cached_data = redis_client.get(f"store_task:{package_name}")
    if not cached_data:
        raise HTTPException(status_code=404, detail="Analysis data not found")

    try:
        raw_data = json.loads(cached_data)
        result_data = raw_data if "sbom" in raw_data else raw_data.get("result", {})

        # --- packages ---
        package_list = []
        for pkg in result_data.get("sbom", {}).get("sbom_data", {}).get("packages", []):
            if pkg.get("name") and pkg.get("versionInfo"):
                package_list.append({
                    "package_name": pkg.get("name"),
                    "version": pkg.get("versionInfo"),
                    "license": pkg.get("licenseDeclared", "NOASSERTION"),
                    "download_link": pkg.get("downloadLocation", "N/A"),
                })

        # --- vulnerabilities ---
        all_vulns = []
        for sca_result in result_data.get("sca", {}).get("Results", []):
            for v in sca_result.get("Vulnerabilities", []):
                all_vulns.append({
                    "cve_id": v.get("VulnerabilityID", "N/A"),
                    "package": v.get("PkgName", "N/A"),
                    "installed_version": v.get("InstalledVersion", "N/A"),
                    "fixed_version": v.get("FixedVersion", "N/A"),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "description": v.get("Description", ""),
                })

        # --- severity distribution ---
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for v in all_vulns:
            sev = v["severity"].upper()
            if sev in severity_count:
                severity_count[sev] += 1

        # --- malicious code ---
        formatted_malicious = []
        for entry in result_data.get("malicious_code", []):
            if not isinstance(entry, dict):
                continue
            rd = entry.get("result", entry)
            formatted_malicious.append({
                "file": entry.get("file", "Unknown"),
                "dangerous_functions": rd.get("dangerous_functions", []),
                "dangerous_functions_lines": rd.get("dangerous_functions_lines", {}),
                "obfuscation_detected": rd.get("obfuscation_detected", False),
                "hardcoded_api_keys": rd.get("hardcoded_api_keys", False),
                "llm_verdict": entry.get("llm_verdict"),
            })

        # --- top vulnerabilities (상위 3개) ---
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        top_vulns = sorted(all_vulns, key=lambda x: severity_order.get(x["severity"], 0), reverse=True)[:3]

        return {
            "repository": package_name,
            "repository_url": "",
            "analysis_date": raw_data.get("analysis_date", ""),
            "security_overview": {
                "title": "보안 분석 개요",
                "total_vulnerabilities": len(all_vulns),
                "missing_packages_count": 0,
                "recommended_updates_count": 0,
                "affected_packages_count": len({v["package"] for v in all_vulns}),
            },
            "severity_distribution": [
                {"level": level, "count": severity_count.get(level, 0)}
                for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
            ],
            "top_vulnerabilities": top_vulns,
            "packages": package_list,
            "package_count": len(package_list),
            "vulnerabilities": all_vulns,
            "vulnerability_count": len(all_vulns),
            "malicious_code_analysis": formatted_malicious,
            "yara_analysis": [],
            "typosquatting_results": result_data.get("typosquatting", []) or [{"message": "No typosquatting detected"}],
            "dependency_confusion_results": result_data.get("dependency_confusion", []) or [{"message": "No dependency confusion detected"}],
            "updates": [],
            "update_recommendations_count": 0,
        }
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Error parsing stored data")


@router.post("/pre-check")
async def pre_check_package(req: PackageRequest):
    """설치 전 타이포스쿼팅 사전 검사. 설치 실패해도 패키지명만으로 위험 판단."""
    from app.services.typosquatting import detect_typosquatting

    name = req.package_name.strip()
    is_typo, official = detect_typosquatting(name)

    result = {
        "package_name": name,
        "typosquatting": {
            "detected": is_typo,
            "official_package": official,
            "warning": f"'{name}'은(는) 정식 패키지 '{official}'의 타이포스쿼팅 의심 패키지입니다." if is_typo else None,
        },
    }

    log.info("pre_check_complete", package=name, typosquatting=is_typo, official=official)
    return result


@router.post("/reset_cache")
async def reset_cache(req: PackageRequest):
    cache_key = f"store_task:{req.package_name}"
    if redis_client.exists(cache_key):
        redis_client.delete(cache_key)
        return {"message": f"Cache cleared: {cache_key}"}
    return {"message": f"No cached data: {cache_key}"}
