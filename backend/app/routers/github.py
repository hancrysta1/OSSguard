import json
from fastapi import APIRouter, HTTPException
from app.schemas.github import GitHubRepo
from app.config import settings
from app.utils.redis_client import redis_client
from app.utils.logging import get_logger
from app.workers.tasks import github_analysis_task

log = get_logger(__name__)
router = APIRouter(prefix="/github", tags=["github"])


def _llm_judge_malware(file_path: str, result_data: dict) -> str | None:
    """LLM 2차 판단: 키워드 탐지된 파일이 진짜 위험한지 판단.
    Returns: "safe", "malicious", or None (LLM 사용 불가 시)
    """
    try:
        import ollama
        # Docker 내부에서 ollama 컨테이너 연결
        client = ollama.Client(host=settings.OLLAMA_HOST)

        # 탐지된 내용 요약
        flags = []
        if result_data.get("dangerous_functions"):
            flags.extend(result_data["dangerous_functions"])
        if result_data.get("obfuscation_detected"):
            flags.append("obfuscation")
        if result_data.get("hardcoded_api_keys"):
            flags.append("hardcoded_secret")

        # 코드 샘플 (탐지된 라인)
        code_lines = []
        for func_lines in result_data.get("dangerous_functions_lines", {}).values():
            for line_info in func_lines:
                code_lines.append(line_info.get("code", ""))
        for line_info in result_data.get("hardcoded_api_lines", []):
            code_lines.append(line_info.get("code", ""))
        code_sample = "; ".join(code_lines[:3]) if code_lines else "N/A"

        prompt = (
            f"Keywords [{', '.join(flags)}] found in {file_path}. "
            f"Code: {code_sample}. "
            f"Is this safe (test dummy, dev config, normal usage) or malicious (real secret, data theft)? "
            f"One word:"
        )

        response = client.chat(
            model=settings.OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": 10},
        )

        answer = response["message"]["content"].strip().lower()
        if "safe" in answer:
            return "safe"
        elif "malicious" in answer:
            return "malicious"
        return None

    except Exception as e:
        log.warning("llm_judge_failed", file=file_path, error=str(e))
        return None


@router.post("/store_analysis")
async def store_analysis_api(repo: GitHubRepo):
    log.info("analysis_requested", url=repo.github_url)
    task = github_analysis_task.delay(repo.github_url)
    return {"task_id": task.id, "message": "Analysis started"}


@router.get("/task_status/{task_id}")
async def get_task_status(task_id: str):
    task = github_analysis_task.AsyncResult(task_id)
    return {"task_id": task_id, "status": task.status, "result": task.result if task.ready() else None}


@router.post("/g_dashboard")
async def github_dashboard(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)
    security_overview = result.get("security_overview", {
        "total_vulnerabilities": 0,
        "severity_count": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "missing_packages_count": 0, "recommended_updates_count": 0, "affected_packages_count": 0,
    })
    severity_count = security_overview.get("severity_count", {})

    # --- packages (SPDX → 변환) ---
    package_list = []
    for pkg in result.get("packages", []):
        download_link = "N/A"
        if "externalRefs" in pkg and isinstance(pkg["externalRefs"], list):
            for ref in pkg["externalRefs"]:
                if ref.get("referenceType") == "purl":
                    download_link = ref.get("referenceLocator", "N/A")
                    break
        package_list.append({
            "package_name": pkg.get("name", pkg.get("package_name", "N/A")),
            "version": pkg.get("versionInfo", pkg.get("version", "N/A")),
            "license": pkg.get("licenseConcluded", pkg.get("license", "N/A")),
            "download_link": download_link,
        })

    # --- vulnerabilities ---
    vuln_list = []
    for vuln in result.get("vulnerabilities", []):
        vuln_list.append({
            "cve_id": vuln.get("cve_id", "N/A"),
            "package": vuln.get("package", "N/A"),
            "installed_version": vuln.get("installed_version", "N/A"),
            "fixed_version": vuln.get("fixed_version", "N/A"),
            "severity": vuln.get("severity", "UNKNOWN"),
        })

    # --- malicious code (result 래핑 풀기 + 캐시된 LLM 판단 읽기) ---
    formatted_malicious = []
    for entry in result.get("malicious_code_analysis", []):
        if not isinstance(entry, dict):
            continue
        rd = entry.get("result", entry)
        formatted_malicious.append({
            "file": entry.get("file", "Unknown"),
            "dangerous_functions": rd.get("dangerous_functions", []),
            "dangerous_functions_lines": rd.get("dangerous_functions_lines", {}),
            "obfuscation_detected": rd.get("obfuscation_detected", False),
            "hardcoded_api_keys": rd.get("hardcoded_api_keys", False),
            "llm_verdict": entry.get("llm_verdict"),  # 워커에서 저장한 값
        })

    # --- yara (result 래핑 풀기) ---
    formatted_yara = []
    for entry in result.get("yara_analysis", []):
        if not isinstance(entry, dict):
            continue
        rd = entry.get("result", entry)
        formatted_yara.append({
            "file": entry.get("file", "Unknown"),
            "yara_matches": rd.get("yara_matches", []),
        })

    # --- typosquatting ---
    typo_formatted = []
    for entry in result.get("typosquatting_analysis", []):
        if "typo_pkg" in entry:
            typo_formatted.append(entry)
    if not typo_formatted:
        typo_formatted = [{"message": "No typosquatting detected"}]

    # --- dependency confusion ---
    dep_formatted = []
    for entry in result.get("dependency_confusion_analysis", []):
        if "dependency" in entry:
            dep_formatted.append(entry)
    if not dep_formatted:
        dep_formatted = [{"message": "No dependency confusion detected"}]

    # --- updates (dict → list 변환) ---
    updates_list = []
    update_recs = result.get("update_recommendations", {})
    if isinstance(update_recs, dict):
        for pkg, details in update_recs.items():
            updates_list.append({
                "package_name": pkg,
                "installed_version": details.get("installed_version", "N/A"),
                "recommended_versions": details.get("recommended_versions", []),
                "severities": details.get("severities", []),
                "cve_list": details.get("cve_list", []),
            })
    elif isinstance(update_recs, list):
        updates_list = update_recs

    return {
        "repository": result.get("repository", "Unknown"),
        "repository_url": repo.github_url,
        "analysis_date": result.get("analysis_date", "Unknown"),
        "security_overview": {
            "title": "보안 분석 개요",
            "total_vulnerabilities": security_overview.get("total_vulnerabilities", 0),
            "missing_packages_count": security_overview.get("missing_packages_count", 0),
            "recommended_updates_count": security_overview.get("recommended_updates_count", 0),
            "affected_packages_count": security_overview.get("affected_packages_count", 0),
        },
        "severity_distribution": [
            {"level": level, "count": severity_count.get(level, 0)}
            for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        ],
        "top_vulnerabilities": result.get("top_vulnerabilities", []),
        "packages": package_list,
        "package_count": len(package_list),
        "vulnerabilities": vuln_list,
        "vulnerability_count": len(vuln_list),
        "malicious_code_analysis": formatted_malicious,
        "yara_analysis": formatted_yara,
        "typosquatting_results": typo_formatted,
        "dependency_confusion_results": dep_formatted,
        "updates": updates_list,
        "update_recommendations_count": len(updates_list),
    }


@router.post("/malicious_code")
async def malicious_code_analysis(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)
    malicious_code_result = result.get("malicious_code_analysis", [])
    yara_result = result.get("yara_analysis", [])

    if not isinstance(malicious_code_result, list):
        malicious_code_result = []
    if not isinstance(yara_result, list):
        yara_result = []

    formatted_malicious = []
    for entry in malicious_code_result:
        if not isinstance(entry, dict):
            continue
        result_data = entry.get("result", {})
        formatted_malicious.append({
            "file": entry.get("file", "Unknown"),
            "dangerous_functions": result_data.get("dangerous_functions", []),
            "obfuscation_detected": result_data.get("obfuscation_detected", False),
            "hardcoded_api_keys": result_data.get("hardcoded_api_keys", False),
        })

    formatted_yara = []
    for entry in yara_result:
        if not isinstance(entry, dict):
            continue
        result_data = entry.get("result", {})
        formatted_yara.append({
            "file": entry.get("file", "Unknown"),
            "yara_matches": result_data.get("yara_matches", []),
        })

    return {
        "repository": result.get("repository", "Unknown"),
        "analysis_date": result.get("analysis_date", "Unknown"),
        "malicious_code_analysis": formatted_malicious,
        "yara_analysis": formatted_yara,
    }


@router.post("/malicious_code/text")
async def malicious_code_analysis_text(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)
    malicious_code_result = result.get("malicious_code_analysis", [])
    yara_result = result.get("yara_analysis", [])

    output = []
    for entry in malicious_code_result:
        if not isinstance(entry, dict) or "result" not in entry:
            continue
        file_name = entry["file"]
        result_data = entry["result"]

        output.append(f"\nString-based malicious code detection:")
        output.append(f"- File: {file_name}")

        for func in result_data.get("dangerous_functions", []):
            output.append(f"  - Dangerous function: {func}")
        for func, lines in result_data.get("dangerous_functions_lines", {}).items():
            output.append(f"  - '{func}' found at:")
            for line in lines:
                output.append(f"    - Line {line['line']}: {line['code']}")
        if result_data.get("obfuscation_detected"):
            output.append("  - Obfuscation detected:")
            for obf in result_data.get("obfuscation_lines", []):
                output.append(f"    - Line {obf['line']} ({obf['keyword']}): {obf['code']}")
        if result_data.get("hardcoded_api_keys"):
            output.append("  - Hardcoded API keys found:")
            for key in result_data.get("hardcoded_api_lines", []):
                output.append(f"    - Line {key['line']}: {key['code']}")
        if result_data.get("details"):
            output.append(f"  - Details: {result_data['details']}")

    for entry in yara_result:
        if not isinstance(entry, dict) or "result" not in entry:
            continue
        yara_matches = entry["result"].get("yara_matches", [])
        if yara_matches:
            output.append(f"\nYARA analysis:")
            output.append(f"- File: {entry['file']}")
            output.append(f"  - Matched rules: {', '.join(yara_matches)}")

    return "\n".join(output)


@router.post("/typosquatting")
async def typosquatting_analysis(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)
    typo_results = result.get("typosquatting_analysis", [])

    formatted = []
    for entry in typo_results:
        if "typo_pkg" in entry:
            formatted.append({
                "file": result.get("repository", "") + "/requirements.txt",
                "line": entry.get("line", "Unknown"),
                "pkg_line": entry.get("pkg_line", ""),
                "similarity": round(entry.get("similarity", 0), 2),
                "typo_pkg": entry.get("typo_pkg", ""),
                "official_pkg": entry.get("official_pkg", ""),
            })

    if not formatted:
        formatted = [{"message": "No typosquatting detected"}]

    return {
        "repository": result.get("repository", "Unknown"),
        "analysis_date": result.get("analysis_date", "Unknown"),
        "typosquatting_results": formatted,
    }


@router.post("/dependency_confusion")
async def dependency_confusion_analysis(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)
    dep_results = result.get("dependency_confusion_analysis", [])

    formatted = []
    for entry in dep_results:
        if "dependency" in entry:
            formatted.append({
                "file": result.get("repository", "") + "/internal_deps.txt",
                "line": entry.get("line", "Unknown"),
                "dependency": entry.get("dependency", ""),
                "distributor": entry.get("distributor", ""),
                "risk": entry.get("risk", ""),
            })

    if not formatted:
        formatted = [{"message": "No dependency confusion detected"}]

    return {
        "repository": result.get("repository", "Unknown"),
        "analysis_date": result.get("analysis_date", "Unknown"),
        "dependency_confusion_results": formatted,
    }


@router.post("/packages")
async def packages(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)
    package_list = []
    for pkg in result.get("packages", []):
        download_link = "N/A"
        if "externalRefs" in pkg and isinstance(pkg["externalRefs"], list):
            for ref in pkg["externalRefs"]:
                if ref.get("referenceType") == "purl":
                    download_link = ref.get("referenceLocator", "N/A")
                    break
                elif ref.get("referenceType") == "cpe23Type" and download_link == "N/A":
                    download_link = ref.get("referenceLocator", "N/A")

        package_list.append({
            "package_name": pkg.get("name", "N/A"),
            "version": pkg.get("versionInfo", "N/A"),
            "license": pkg.get("licenseConcluded", "NOASSERTION"),
            "download_link": download_link,
        })

    return {
        "repository": result.get("repository", "Unknown"),
        "analysis_date": result.get("analysis_date", "Unknown"),
        "package_count": len(package_list),
        "packages": package_list,
    }


@router.post("/vulnerabilities")
async def vulnerabilities(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)
    vuln_list = []
    for vuln in result.get("vulnerabilities", result.get("top_vulnerabilities", [])):
        vuln_list.append({
            "cve_id": vuln.get("cve_id", "N/A"),
            "package": vuln.get("package", "N/A"),
            "installed_version": vuln.get("installed_version", vuln.get("fix_version", "N/A")),
            "severity": vuln.get("severity", "UNKNOWN"),
        })

    return {
        "repository": result.get("repository", "Unknown"),
        "analysis_date": result.get("analysis_date", "Unknown"),
        "vulnerability_count": len(vuln_list),
        "vulnerabilities": vuln_list,
    }


@router.post("/updates")
async def updates(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)
    updates_list = []
    update_recs = result.get("update_recommendations", {})

    if isinstance(update_recs, list):
        for entry in update_recs:
            updates_list.append({
                "package_name": entry.get("package_name", "unknown"),
                "installed_version": entry.get("installed_version", "N/A"),
                "recommended_versions": entry.get("recommended_versions", []),
                "severities": entry.get("severities", []),
                "cve_list": entry.get("cve_list", []),
            })
    elif isinstance(update_recs, dict):
        for pkg, details in update_recs.items():
            updates_list.append({
                "package_name": pkg,
                "installed_version": details.get("installed_version", "N/A"),
                "recommended_versions": details.get("recommended_versions", []),
                "severities": details.get("severities", []),
                "cve_list": details.get("cve_list", []),
            })

    return {
        "repository": result.get("repository", "Unknown"),
        "analysis_date": result.get("analysis_date", "Unknown"),
        "update_recommendations_count": len(updates_list),
        "updates": updates_list,
    }


@router.post("/reset_cache")
async def reset_cache(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cache_key = f"dashboard:{repository_name}"
    if redis_client.exists(cache_key):
        redis_client.delete(cache_key)
        return {"message": f"Cache cleared: {cache_key}"}
    return {"message": f"No cached data: {cache_key}"}


@router.post("/ai_insights")
async def ai_insights(repo: GitHubRepo):
    repository_name = repo.github_url.split("/")[-1]
    cached_data = redis_client.get(f"dashboard:{repository_name}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Run /store_analysis first")

    result = json.loads(cached_data)

    from app.services.ai.risk_scorer import calculate_risk_score
    from app.services.ai.summarizer import generate_security_summary
    from app.services.ai.vulnerability_prioritizer import prioritize_vulnerabilities

    risk_score = calculate_risk_score(result)
    summary = await generate_security_summary(result)
    prioritized_vulns = await prioritize_vulnerabilities(result.get("vulnerabilities", result.get("top_vulnerabilities", [])))

    return {
        "repository": result.get("repository", "Unknown"),
        "analysis_date": result.get("analysis_date", "Unknown"),
        "risk_score": risk_score,
        "ai_summary": summary,
        "prioritized_vulnerabilities": prioritized_vulns[:10],
    }
