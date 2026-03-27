import os
import re
import sys
import json
import shutil
import subprocess
import time
from datetime import datetime

from app.workers.celery_app import celery_app
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


def _get_redis():
    import redis
    return redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB, decode_responses=True)


def _llm_filter_malware(malicious_results: list) -> list:
    """LLM 2차 판단: 키워드 탐지된 파일이 진짜 위험한지 판단하여 llm_verdict 추가."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    try:
        import ollama
        client = ollama.Client(host=settings.OLLAMA_HOST)
    except Exception:
        return malicious_results  # ollama 없으면 그대로 반환

    # LLM 판단이 필요한 항목만 필터
    entries_to_judge = []
    for entry in malicious_results:
        if not isinstance(entry, dict):
            continue
        rd = entry.get("result", entry)
        has_flags = (
            rd.get("dangerous_functions")
            or rd.get("obfuscation_detected")
            or rd.get("hardcoded_api_keys")
        )
        if has_flags:
            entries_to_judge.append(entry)

    if not entries_to_judge:
        return malicious_results

    def _judge_single(entry):
        rd = entry.get("result", entry)
        flags = []
        if rd.get("dangerous_functions"):
            flags.extend(rd["dangerous_functions"])
        if rd.get("obfuscation_detected"):
            flags.append("obfuscation")
        if rd.get("hardcoded_api_keys"):
            flags.append("hardcoded_secret")

        code_lines = []
        for func_lines in rd.get("dangerous_functions_lines", {}).values():
            for li in func_lines:
                code_lines.append(li.get("code", ""))
        for li in rd.get("hardcoded_api_lines", []):
            code_lines.append(li.get("code", ""))
        code_sample = "; ".join(code_lines[:3]) if code_lines else "N/A"

        file_path = entry.get("file", "")
        prompt = (
            f"Keywords [{', '.join(flags)}] found in {file_path}. "
            f"Code: {code_sample}. "
            f"Is this safe (test dummy, dev config, normal usage) or malicious (real secret, data theft)? "
            f"One word:"
        )

        try:
            response = client.chat(
                model=settings.OLLAMA_MODEL,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1, "num_predict": 10},
            )
            answer = response["message"]["content"].strip().lower()
            if "safe" in answer:
                entry["llm_verdict"] = "safe"
            elif "malicious" in answer:
                entry["llm_verdict"] = "malicious"
            else:
                entry["llm_verdict"] = None
        except Exception as e:
            log.warning("llm_filter_timeout", file=file_path, error=str(e))
            entry["llm_verdict"] = None

    # 병렬로 LLM 호출 (최대 4개 동시)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_judge_single, entry) for entry in entries_to_judge]
        for f in as_completed(futures):
            f.result()  # 예외 전파

    return malicious_results


def _publish_progress(task_id: str, stage: str, status: str, progress: int, message: str):
    r = _get_redis()
    data = json.dumps({"stage": stage, "status": status, "progress": progress, "message": message})
    r.publish(f"analysis_progress:{task_id}", data)


def _clone_repo(github_url: str, task_id: str | None = None) -> str | None:
    match = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", github_url)
    if not match:
        return None
    _, repo_name = match.groups()
    repo_path = os.path.abspath(f"./{repo_name}")
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

    # Shallow clone (--depth 1): skip git history, much faster for large repos
    cmd = ["git", "clone", "--depth", "1", github_url, repo_path]

    if task_id:
        _publish_progress(task_id, "clone", "running", 12, f"Cloning {repo_name} (shallow)...")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        log.error("clone_failed", error=result.stderr)
        return None
    return repo_path


@celery_app.task(bind=True)
def github_analysis_task(self, github_url: str):
    task_id = self.request.id
    from app.services.sbom import generate_sbom
    from app.services.sca import (analyze_sca, get_top_vulnerabilities, get_vulnerability_analysis,
                                  get_update_recommendations, summarize_security_analysis)
    from app.services.malware import scan_directory_for_malware
    from app.services.typosquatting import run_typosquatting_check
    from app.services.dependency_confusion import check_dependency_confusion
    from app.services.ai.risk_scorer import calculate_risk_score

    r = _get_redis()
    r.set(f"task_status:{task_id}", "running")

    try:
        # Clone
        _publish_progress(task_id, "clone", "running", 10, "Cloning repository...")
        repo_path = _clone_repo(github_url, task_id)
        if not repo_path:
            _publish_progress(task_id, "clone", "failed", 10, "Clone failed")
            r.set(f"task_status:{task_id}", "failed")
            return {"error": "Clone failed"}
        _publish_progress(task_id, "clone", "completed", 15, "Clone complete")

        # SBOM
        _publish_progress(task_id, "sbom", "running", 20, "Generating SBOM...")
        output_folder = os.path.join(repo_path, "_output")
        os.makedirs(output_folder, exist_ok=True)
        try:
            sbom_file, sbom_data = generate_sbom(repo_path, output_folder)
        except Exception as e:
            log.error("sbom_failed", error=str(e))
            sbom_data = {"packages": []}
            sbom_file = ""
        _publish_progress(task_id, "sbom", "completed", 30, "SBOM generated")

        # SCA
        _publish_progress(task_id, "sca", "running", 35, "Running vulnerability analysis...")
        try:
            _, sca_data = analyze_sca(sbom_file, output_folder)
        except Exception as e:
            log.error("sca_failed", error=str(e))
            sca_data = {"Results": []}
        _publish_progress(task_id, "sca", "completed", 50, "Vulnerability analysis complete")

        # Malware
        _publish_progress(task_id, "malware", "running", 55, "Scanning for malware...")
        malicious_results, yara_results = scan_directory_for_malware(repo_path)
        _publish_progress(task_id, "malware", "completed", 62, "Malware scan complete")

        # LLM 2차 판단 (오탐 필터링)
        _publish_progress(task_id, "malware", "running", 63, "AI analyzing flagged files...")
        malicious_results = _llm_filter_malware(malicious_results)
        _publish_progress(task_id, "malware", "completed", 65, "AI malware analysis complete")

        # Typosquatting
        _publish_progress(task_id, "typosquatting", "running", 70, "Checking typosquatting...")
        requirements_path = os.path.join(repo_path, "requirements.txt")
        typo_results = run_typosquatting_check(requirements_path)
        _publish_progress(task_id, "typosquatting", "completed", 75, "Typosquatting check complete")

        # Dependency Confusion
        _publish_progress(task_id, "dependency_confusion", "running", 80, "Checking dependency confusion...")
        internal_deps_file = os.path.join(repo_path, "internal_deps.txt")
        dep_confusion_results = check_dependency_confusion(internal_deps_file)
        _publish_progress(task_id, "dependency_confusion", "completed", 85, "Dependency confusion check complete")

        # AI Risk Score
        _publish_progress(task_id, "ai", "running", 90, "Calculating risk score...")
        security_overview = summarize_security_analysis(sca_data, sbom_data, requirements_path)

        analysis_result = {
            "repository": repo_path.split("/")[-1] if "/" in repo_path else repo_path,
            "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "package_count": len(sbom_data.get("packages", [])),
            "security_overview": security_overview,
            "top_vulnerabilities": get_top_vulnerabilities(sca_data),
            "packages": sbom_data.get("packages", []),
            "vulnerabilities": get_vulnerability_analysis(sca_data),
            "update_recommendations": get_update_recommendations(sca_data),
            "typosquatting_analysis": typo_results,
            "dependency_confusion_analysis": dep_confusion_results,
            "malicious_code_analysis": malicious_results,
            "yara_analysis": yara_results,
        }

        # Calculate risk score
        risk_score = calculate_risk_score(analysis_result)
        analysis_result["risk_score"] = risk_score

        _publish_progress(task_id, "ai", "completed", 95, "AI analysis complete")

        # Store in Redis
        repository_name = github_url.split("/")[-1]
        r.set(f"dashboard:{repository_name}", json.dumps(analysis_result))
        r.set(f"task_status:{task_id}", "completed")
        _publish_progress(task_id, "done", "completed", 100, "Analysis complete")

        log.info("analysis_complete", repository=repository_name)
        return analysis_result

    except Exception as e:
        log.error("analysis_failed", error=str(e))
        r.set(f"task_status:{task_id}", "failed")
        _publish_progress(task_id, "error", "failed", 0, str(e))
        return {"error": str(e)}


@celery_app.task(bind=True)
def install_package_task(self, package_manager: str, package_name: str, package_version: str = None):
    start_time = time.time()
    install_dir = os.path.join(os.getcwd(), f"{package_name}-{package_version}" if package_version else package_name)

    if os.path.exists(install_dir):
        shutil.rmtree(install_dir)
    os.makedirs(install_dir, exist_ok=True)

    if package_manager == "pypi":
        pkg_spec = f"{package_name}=={package_version}" if package_version else package_name
        cmd = [sys.executable, "-m", "pip", "install", "--target", install_dir, pkg_spec]
    elif package_manager == "npm":
        pkg_spec = f"{package_name}@{package_version}" if package_version else package_name
        cmd = ["npm", "install", pkg_spec, "--prefix", install_dir]
    else:
        return {"success": False, "message": "Unsupported package manager"}

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        elapsed = round(time.time() - start_time, 2)
        result = {"success": True, "message": f"{package_name} installed", "install_path": install_dir, "elapsed_time": elapsed}
        r = _get_redis()
        r.set(f"install_task:{self.request.id}", json.dumps(result))
        return result
    except subprocess.CalledProcessError as e:
        elapsed = round(time.time() - start_time, 2)
        error_data = {"success": False, "message": f"Installation failed: {e.stderr}", "elapsed_time": elapsed}
        r = _get_redis()
        r.set(f"install_task:{self.request.id}", json.dumps(error_data))
        return error_data


@celery_app.task(bind=True)
def package_analysis_task(self, package_manager: str, package_name: str, package_version: str = None):
    from app.services.sbom import generate_sbom_for_package
    from app.services.sca import analyze_sca_for_package
    from app.services.malware import scan_directory_for_malware

    r = _get_redis()
    task_id = self.request.id
    r.set(f"task_status:{task_id}", "running")

    try:
        start_time = time.time()
        package_folder = f"{package_name}-{package_version}" if package_version else package_name
        package_path = os.path.join(os.getcwd(), package_folder)

        if not os.path.exists(package_path):
            _publish_progress(task_id, "error", "failed", 0, f"Package not installed: {package_path}")
            r.set(f"task_status:{task_id}", "failed")
            raise Exception(f"Package not installed: {package_path}")

        # SBOM
        _publish_progress(task_id, "sbom", "running", 15, "Generating SBOM...")
        sbom_data = generate_sbom_for_package(package_path)
        _publish_progress(task_id, "sbom", "completed", 30, "SBOM generated")

        # SCA
        _publish_progress(task_id, "sca", "running", 35, "Running vulnerability analysis...")
        sca_data = analyze_sca_for_package(sbom_data["sbom_path"])
        _publish_progress(task_id, "sca", "completed", 55, "Vulnerability analysis complete")

        # Malware
        _publish_progress(task_id, "malware", "running", 60, "Scanning for malware...")
        malicious_results, _ = scan_directory_for_malware(package_path)
        _publish_progress(task_id, "malware", "completed", 85, "Malware scan complete")

        elapsed = round(time.time() - start_time, 2)

        analysis_result = {
            "sbom": sbom_data,
            "sca": sca_data,
            "malicious_code": malicious_results,
            "typosquatting": [],
            "dependency_confusion": [],
        }

        # Store with BOTH task_id and package_name keys
        r.set(f"store_task:{task_id}", json.dumps(analysis_result))
        r.set(f"store_task:{package_name}", json.dumps(analysis_result))
        r.set(f"task_status:{task_id}", "completed")
        _publish_progress(task_id, "done", "completed", 100, "Analysis complete")

        log.info("package_analysis_complete", package=package_name, elapsed=elapsed)
        return {"success": True, "message": "Analysis complete", "package": package_name, "elapsed_time": elapsed, "result": analysis_result}

    except Exception as e:
        log.error("package_analysis_failed", error=str(e))
        r.set(f"task_status:{task_id}", "failed")
        _publish_progress(task_id, "error", "failed", 0, str(e))
        error_data = {"success": False, "message": str(e)}
        r.set(f"store_task:{task_id}", json.dumps(error_data))
        return error_data
