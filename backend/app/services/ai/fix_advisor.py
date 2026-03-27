"""AI-powered automated fix suggestions for detected vulnerabilities."""

import json
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


async def generate_fix_suggestions(analysis_data: dict) -> list[dict]:
    """Generate actionable fix suggestions for each vulnerability.

    For each CVE, produces:
    - Human-readable explanation of the risk
    - Exact command to fix (pip install, npm install)
    - Code diff suggestion if applicable
    - Priority level
    """
    vulnerabilities = analysis_data.get("top_vulnerabilities", [])
    updates = analysis_data.get("update_recommendations", {})
    malware = analysis_data.get("malicious_code_analysis", [])

    fixes = []

    # 1. CVE fixes
    for vuln in vulnerabilities:
        fix = _build_cve_fix(vuln, updates)
        fixes.append(fix)

    # 2. Malware fixes
    for entry in malware:
        if isinstance(entry, dict) and entry.get("result", {}).get("dangerous_functions"):
            fix = _build_malware_fix(entry)
            fixes.append(fix)

    # 3. AI-enhanced explanations
    fixes = await _enrich_with_ai(fixes)

    # Sort by priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    fixes.sort(key=lambda f: priority_order.get(f.get("priority", "LOW"), 4))

    return fixes


def _build_cve_fix(vuln: dict, updates: dict) -> dict:
    """Build a fix suggestion for a CVE vulnerability."""
    package = vuln.get("package", vuln.get("PkgName", "unknown"))
    cve_id = vuln.get("cve_id", "N/A")
    severity = vuln.get("severity", "UNKNOWN")
    fix_version = vuln.get("fix_version", vuln.get("fixed_version", ""))
    description = vuln.get("description", "")

    # Try to find recommended version from updates
    if isinstance(updates, dict) and package in updates:
        rec = updates[package]
        if isinstance(rec, dict):
            versions = rec.get("recommended_versions", [])
            if versions:
                fix_version = versions[0]

    fix = {
        "type": "cve_fix",
        "cve_id": cve_id,
        "package": package,
        "priority": severity,
        "title": f"{package} 보안 업데이트 ({cve_id})",
        "risk_description": description[:200] if description else f"{severity} 심각도 취약점 발견",
        "commands": [],
        "manual_steps": [],
    }

    if fix_version and fix_version not in ("N/A", "No fix available", ""):
        fix["commands"] = [
            f"pip install {package}>={fix_version}",
            f"# 또는 requirements.txt에서 {package} 버전을 {fix_version} 이상으로 변경",
        ]
        fix["manual_steps"] = [
            f"requirements.txt에서 {package}==[현재버전] → {package}>={fix_version} 변경",
            "pip install -r requirements.txt 실행",
            "테스트 실행하여 호환성 확인",
        ]
    else:
        fix["commands"] = [f"# {package}에 대한 공식 패치가 아직 없습니다"]
        fix["manual_steps"] = [
            f"{package} 사용 부분의 코드를 검토하세요",
            "대체 패키지 사용을 고려하세요",
            f"해당 CVE를 모니터링하세요: https://nvd.nist.gov/vuln/detail/{cve_id}",
        ]

    return fix


def _build_malware_fix(entry: dict) -> dict:
    """Build a fix suggestion for malware detection."""
    file_name = entry.get("file", "unknown")
    result = entry.get("result", {})
    funcs = result.get("dangerous_functions", [])

    fix = {
        "type": "malware_fix",
        "package": file_name,
        "priority": "HIGH",
        "title": f"악성 코드 의심: {file_name}",
        "risk_description": f"위험 함수 감지: {', '.join(set(funcs))}",
        "commands": [],
        "manual_steps": [
            f"{file_name} 파일을 수동으로 코드 리뷰하세요",
        ],
    }

    if "exec" in funcs or "eval" in funcs:
        fix["manual_steps"].append("exec()/eval() 호출을 안전한 대안으로 교체하세요")
        fix["manual_steps"].append("외부 입력이 exec/eval에 전달되지 않는지 확인하세요")
    if "subprocess.Popen" in funcs or "os.system" in funcs:
        fix["manual_steps"].append("시스템 명령어 실행이 의도된 동작인지 확인하세요")
        fix["manual_steps"].append("subprocess.run()에 shell=False를 사용하세요")
    if result.get("hardcoded_api_keys"):
        fix["manual_steps"].append("하드코딩된 키를 환경변수로 이동하세요")
        fix["commands"].append("# .env 파일로 비밀 키를 분리하세요")

    return fix


async def _enrich_with_ai(fixes: list[dict]) -> list[dict]:
    """Use Ollama to add detailed Korean explanations to each fix."""
    if not fixes:
        return fixes

    try:
        import ollama

        # Batch all fixes into one prompt for efficiency
        fixes_summary = json.dumps(
            [{"title": f["title"], "priority": f["priority"], "risk": f["risk_description"]} for f in fixes[:10]],
            ensure_ascii=False,
        )

        prompt = f"""당신은 보안 엔지니어입니다. 다음 보안 이슈들에 대해 각각 1-2문장으로 실무자가 이해하기 쉬운 한국어 설명을 작성해주세요.

이슈 목록:
{fixes_summary}

JSON 배열로만 응답하세요:
[{{"title": "...", "explanation": "이해하기 쉬운 설명"}}]"""

        response = ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3, "num_predict": 1024},
        )

        content = response["message"]["content"]
        start = content.find("[")
        end = content.rfind("]") + 1
        if start >= 0 and end > start:
            explanations = json.loads(content[start:end])
            explain_map = {e["title"]: e["explanation"] for e in explanations if "title" in e}
            for fix in fixes:
                if fix["title"] in explain_map:
                    fix["ai_explanation"] = explain_map[fix["title"]]

    except Exception as e:
        log.warning("fix_ai_enrichment_failed", error=str(e))

    return fixes
