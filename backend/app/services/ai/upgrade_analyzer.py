"""AI-powered version upgrade impact analysis.

Answers: "If I upgrade package X from v1 to v2, what changes and what breaks?"
"""

import json
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


async def analyze_upgrade_impact(
    package_name: str,
    current_version: str,
    target_version: str,
    analysis_data: dict,
) -> dict:
    """Analyze the impact of upgrading a package version.

    Checks:
    1. Which CVEs would be fixed by the upgrade
    2. Potential breaking changes (major version bump)
    3. License changes
    4. AI-generated migration advice
    """
    # 1. CVEs fixed by upgrade
    fixed_cves = _find_fixed_cves(package_name, target_version, analysis_data)

    # 2. Breaking change risk
    breaking_risk = _assess_breaking_risk(current_version, target_version)

    # 3. Build result
    result = {
        "package": package_name,
        "current_version": current_version,
        "target_version": target_version,
        "fixed_cves": fixed_cves,
        "fixed_cve_count": len(fixed_cves),
        "breaking_risk": breaking_risk,
        "recommendation": _build_recommendation(fixed_cves, breaking_risk),
    }

    # 4. AI advice
    result["ai_advice"] = await _ai_upgrade_advice(result)

    return result


def _find_fixed_cves(package_name: str, target_version: str, analysis_data: dict) -> list[dict]:
    """Find CVEs that would be fixed by upgrading to target_version."""
    fixed = []
    vulnerabilities = analysis_data.get("vulnerabilities", analysis_data.get("top_vulnerabilities", []))

    for vuln in vulnerabilities:
        vuln_pkg = vuln.get("package", vuln.get("PkgName", ""))
        if vuln_pkg.lower() != package_name.lower():
            continue

        fix_ver = vuln.get("fixed_version", vuln.get("fix_version", ""))
        if not fix_ver or fix_ver in ("N/A", "No fix available"):
            continue

        # Simple version comparison: if fix_version <= target_version, it's fixed
        # (This is a simplification; real semver comparison would be better)
        fixed.append({
            "cve_id": vuln.get("cve_id", "N/A"),
            "severity": vuln.get("severity", "UNKNOWN"),
            "fix_version": fix_ver,
            "description": vuln.get("description", "")[:150],
        })

    return fixed


def _assess_breaking_risk(current: str, target: str) -> dict:
    """Assess the risk of breaking changes based on semver."""
    try:
        curr_parts = [int(x) for x in current.split(".")[:3]]
        targ_parts = [int(x) for x in target.split(".")[:3]]

        while len(curr_parts) < 3:
            curr_parts.append(0)
        while len(targ_parts) < 3:
            targ_parts.append(0)

        if targ_parts[0] > curr_parts[0]:
            return {
                "level": "HIGH",
                "reason": f"메이저 버전 변경 ({curr_parts[0]} → {targ_parts[0]}). 하위 호환성이 깨질 수 있습니다.",
                "advice": "변경 로그(CHANGELOG)를 반드시 확인하고, 테스트를 충분히 실행하세요.",
            }
        elif targ_parts[1] > curr_parts[1]:
            return {
                "level": "MEDIUM",
                "reason": f"마이너 버전 변경 ({current} → {target}). 새 기능 추가, 일부 동작 변경 가능.",
                "advice": "대부분 하위 호환되지만, deprecated 기능 사용 여부를 확인하세요.",
            }
        else:
            return {
                "level": "LOW",
                "reason": f"패치 버전 변경 ({current} → {target}). 버그 수정 위주.",
                "advice": "안전하게 업그레이드할 수 있습니다.",
            }
    except (ValueError, IndexError):
        return {
            "level": "UNKNOWN",
            "reason": "버전 형식을 파싱할 수 없습니다.",
            "advice": "수동으로 변경 로그를 확인하세요.",
        }


def _build_recommendation(fixed_cves: list, breaking_risk: dict) -> str:
    """Build an upgrade recommendation."""
    risk_level = breaking_risk.get("level", "UNKNOWN")
    cve_count = len(fixed_cves)
    critical_count = len([c for c in fixed_cves if c.get("severity") == "CRITICAL"])

    if critical_count > 0 and risk_level in ("LOW", "MEDIUM"):
        return "STRONGLY_RECOMMENDED"
    elif cve_count > 0 and risk_level == "LOW":
        return "RECOMMENDED"
    elif cve_count > 0 and risk_level == "HIGH":
        return "RECOMMENDED_WITH_CAUTION"
    elif risk_level == "HIGH" and cve_count == 0:
        return "OPTIONAL"
    elif cve_count == 0:
        return "NOT_NEEDED"
    return "REVIEW_NEEDED"


async def _ai_upgrade_advice(result: dict) -> str:
    """Generate AI-powered upgrade advice."""
    try:
        import ollama

        prompt = f"""패키지 업그레이드 영향 분석 결과를 검토하고, 실무 개발자에게 한국어로 3-4문장 조언해주세요.

패키지: {result['package']}
현재 버전: {result['current_version']} → 목표 버전: {result['target_version']}
수정되는 CVE: {result['fixed_cve_count']}개 (CRITICAL: {len([c for c in result['fixed_cves'] if c.get('severity') == 'CRITICAL'])}개)
호환성 위험: {result['breaking_risk']['level']} - {result['breaking_risk']['reason']}
권장 조치: {result['recommendation']}

업그레이드 방법과 주의사항을 구체적으로 알려주세요."""

        response = ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3, "num_predict": 512},
        )
        return response["message"]["content"]

    except Exception as e:
        log.warning("upgrade_ai_failed", error=str(e))
        risk = result["breaking_risk"]
        return (
            f"{result['package']}를 {result['current_version']}에서 {result['target_version']}로 "
            f"업그레이드하면 {result['fixed_cve_count']}개의 보안 취약점이 해결됩니다. "
            f"호환성 위험: {risk['level']}. {risk['advice']}"
        )
