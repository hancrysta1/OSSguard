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
    # Fix: try both key patterns for backwards compatibility
    cached_data = redis_client.get(f"store_task:{package_name}")
    if not cached_data:
        # Try finding by scanning recent task keys
        raise HTTPException(status_code=404, detail="Analysis data not found")

    try:
        raw_data = json.loads(cached_data)
        result_data = raw_data if "sbom" in raw_data else raw_data.get("result", {})

        sca_results = result_data.get("sca", {}).get("Results", [])
        vulnerabilities = []
        if sca_results:
            vulnerabilities = sca_results[0].get("Vulnerabilities", [])

        return {
            "status": raw_data.get("status", "SUCCESS"),
            "result": {
                "success": result_data.get("success", True),
                "package": result_data.get("package", package_name),
                "sbom": {
                    "packages": [
                        {
                            "name": pkg.get("name"),
                            "version": pkg.get("versionInfo"),
                            "license": pkg.get("licenseDeclared"),
                            "download_location": pkg.get("downloadLocation"),
                        }
                        for pkg in result_data.get("sbom", {}).get("sbom_data", {}).get("packages", [])
                        if pkg.get("name") and pkg.get("versionInfo")
                    ],
                },
                "sca": {
                    "total_vulnerabilities": len(vulnerabilities),
                    "vulnerabilities": [
                        {
                            "cve_id": v.get("VulnerabilityID"),
                            "package": v.get("PkgName"),
                            "installed_version": v.get("InstalledVersion"),
                            "fixed_version": v.get("FixedVersion"),
                            "severity": v.get("Severity"),
                            "description": v.get("Description"),
                        }
                        for v in vulnerabilities
                    ],
                },
                "malicious_code": result_data.get("malicious_code", {}),
                "typosquatting": result_data.get("typosquatting", []),
                "dependency_confusion": result_data.get("dependency_confusion", []),
            },
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
