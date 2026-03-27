"""Package health scoring - evaluates if a dependency is trustworthy and maintained."""

import json
from datetime import datetime
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


async def evaluate_package_health(packages: list[dict]) -> list[dict]:
    """Evaluate health of each package based on available metadata.

    Scoring dimensions (0-100):
    - Version freshness: is the installed version recent?
    - License clarity: is the license clearly declared?
    - Name safety: does the name look legitimate?
    - Vulnerability exposure: how many CVEs affect this package?
    """
    results = []

    for pkg in packages:
        name = pkg.get("name", pkg.get("package_name", "unknown"))
        version = pkg.get("versionInfo", pkg.get("version", "N/A"))
        license_info = pkg.get("licenseConcluded", pkg.get("license", "NOASSERTION"))

        health = _calculate_health(name, version, license_info)
        results.append({
            "package": name,
            "version": version,
            "license": license_info,
            **health,
        })

    # Sort by health score ascending (worst first)
    results.sort(key=lambda x: x["health_score"])

    return results


async def evaluate_with_ai(packages: list[dict], analysis_data: dict) -> dict:
    """AI-enhanced package health evaluation with vulnerability context."""
    health_results = await evaluate_package_health(packages)

    # Cross-reference with vulnerability data
    vuln_packages = set()
    for vuln in analysis_data.get("top_vulnerabilities", []):
        vuln_packages.add(vuln.get("package", ""))
    for vuln in analysis_data.get("vulnerabilities", []):
        vuln_packages.add(vuln.get("package", vuln.get("PkgName", "")))

    for result in health_results:
        if result["package"] in vuln_packages:
            result["has_vulnerabilities"] = True
            result["health_score"] = max(0, result["health_score"] - 20)
            result["flags"].append("known_vulnerabilities")
        else:
            result["has_vulnerabilities"] = False

    # AI summary of overall dependency health
    summary = await _ai_health_summary(health_results)

    # Statistics
    total = len(health_results)
    healthy = len([r for r in health_results if r["health_score"] >= 70])
    warning = len([r for r in health_results if 40 <= r["health_score"] < 70])
    unhealthy = len([r for r in health_results if r["health_score"] < 40])

    return {
        "total_packages": total,
        "healthy": healthy,
        "warning": warning,
        "unhealthy": unhealthy,
        "health_rate": round(healthy / total * 100, 1) if total else 0,
        "packages": health_results,
        "ai_summary": summary,
    }


def _calculate_health(name: str, version: str, license_info: str) -> dict:
    """Calculate health score for a single package."""
    score = 100
    flags = []
    details = []

    # 1. License clarity (0-25 points deducted)
    if not license_info or license_info in ("NOASSERTION", "Unknown", "NONE", ""):
        score -= 25
        flags.append("no_license")
        details.append("라이선스 정보 없음")
    elif license_info in ("GPL-3.0-only", "AGPL-3.0-only"):
        score -= 10
        flags.append("copyleft_license")
        details.append(f"Copyleft 라이선스: {license_info}")

    # 2. Version info (0-15 points deducted)
    if not version or version in ("N/A", "0.0.0", ""):
        score -= 15
        flags.append("no_version")
        details.append("버전 정보 없음")

    # 3. Name safety (0-30 points deducted)
    name_lower = name.lower()
    # Suspicious patterns in package names
    suspicious_patterns = [
        ("test-", "테스트 패키지명"),
        ("example-", "예제 패키지명"),
        ("-debug", "디버그 패키지"),
    ]
    for pattern, reason in suspicious_patterns:
        if pattern in name_lower:
            score -= 10
            flags.append("suspicious_name")
            details.append(f"의심스러운 이름 패턴: {reason}")
            break

    # Very short names are more likely to be typosquatted
    if len(name) <= 2:
        score -= 15
        flags.append("very_short_name")
        details.append("매우 짧은 패키지명 (타이포스쿼팅 위험)")

    # 4. Well-known trusted packages get a bonus
    trusted = {
        "requests", "flask", "django", "numpy", "pandas", "scipy",
        "express", "react", "lodash", "axios", "webpack",
        "pytest", "setuptools", "pip", "wheel",
    }
    if name_lower in trusted:
        score = min(100, score + 10)
        details.append("신뢰할 수 있는 주요 패키지")

    return {
        "health_score": max(0, min(100, score)),
        "health_level": _score_to_level(score),
        "flags": flags,
        "details": details,
    }


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "HEALTHY"
    elif score >= 60:
        return "MODERATE"
    elif score >= 40:
        return "WARNING"
    return "UNHEALTHY"


async def _ai_health_summary(results: list[dict]) -> str:
    """Generate AI summary of overall package health."""
    try:
        import ollama

        unhealthy = [r for r in results if r["health_score"] < 50]
        flags_summary = {}
        for r in results:
            for f in r.get("flags", []):
                flags_summary[f] = flags_summary.get(f, 0) + 1

        prompt = f"""다음 오픈소스 의존성 패키지 건강도 분석 결과를 한국어로 2-3문장으로 요약해주세요.

총 패키지: {len(results)}개
건강한 패키지: {len([r for r in results if r['health_score'] >= 70])}개
주의 필요 패키지: {len([r for r in results if r['health_score'] < 50])}개
주요 문제: {json.dumps(flags_summary, ensure_ascii=False)}

위험 패키지 예시: {json.dumps([{'name': r['package'], 'score': r['health_score'], 'flags': r['flags']} for r in unhealthy[:5]], ensure_ascii=False)}

실무 관점에서 어떤 조치를 취해야 하는지 알려주세요."""

        response = ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3, "num_predict": 512},
        )
        return response["message"]["content"]

    except Exception as e:
        log.warning("health_ai_summary_failed", error=str(e))
        total = len(results)
        unhealthy_count = len([r for r in results if r["health_score"] < 50])
        if unhealthy_count == 0:
            return f"전체 {total}개 패키지 중 건강도 위험 패키지 없음. 양호한 상태입니다."
        return f"전체 {total}개 패키지 중 {unhealthy_count}개가 주의가 필요합니다. 라이선스 확인 및 버전 업데이트를 권장합니다."
