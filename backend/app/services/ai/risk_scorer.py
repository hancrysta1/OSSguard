"""Comprehensive risk scoring with weighted multi-dimensional analysis."""

from app.utils.logging import get_logger

log = get_logger(__name__)


def calculate_risk_score(analysis_data: dict) -> dict:
    """Calculate overall risk score (0-100) from analysis data.

    Scoring dimensions:
    - CVE vulnerabilities: max 60 points (weighted by severity)
    - Typosquatting: max 15 points
    - Dependency confusion: max 15 points
    - Malware detection: max 10 points

    Returns dict with score, level, summary, and breakdown.
    """
    overview = analysis_data.get("security_overview", {})
    severity_count = overview.get("severity_count", {})

    # --- CVE Score (max 60) ---
    cve_score = min(60, (
        severity_count.get("CRITICAL", 0) * 15
        + severity_count.get("HIGH", 0) * 8
        + severity_count.get("MEDIUM", 0) * 3
        + severity_count.get("LOW", 0) * 1
    ))

    # --- Typosquatting Score (max 15) ---
    typo_results = analysis_data.get("typosquatting_analysis", [])
    typo_count = sum(1 for t in typo_results if isinstance(t, dict) and "typo_pkg" in t)
    typo_score = min(15, typo_count * 5)

    # --- Dependency Confusion Score (max 15) ---
    dep_results = analysis_data.get("dependency_confusion_analysis", [])
    dep_count = sum(1 for d in dep_results if isinstance(d, dict) and "risk" in d)
    dep_score = min(15, dep_count * 5)

    # --- Malware Score (max 10) ---
    malware_results = analysis_data.get("malicious_code_analysis", [])
    malware_count = 0
    for m in malware_results:
        if isinstance(m, dict):
            result = m.get("result", {})
            if isinstance(result, dict):
                if result.get("dangerous_functions"):
                    malware_count += 2
                if result.get("obfuscation_detected"):
                    malware_count += 1
                if result.get("hardcoded_api_keys"):
                    malware_count += 1
    malware_score = min(10, malware_count)

    # YARA bonus
    yara_results = analysis_data.get("yara_analysis", [])
    yara_hits = sum(1 for y in yara_results if isinstance(y, dict) and y.get("result", {}).get("yara_matches"))
    malware_score = min(10, malware_score + yara_hits * 2)

    # --- Total ---
    total = min(100, cve_score + typo_score + dep_score + malware_score)

    if total >= 70:
        level = "CRITICAL"
        summary = "심각한 보안 위험이 감지되었습니다. 즉시 대응이 필요합니다."
    elif total >= 50:
        level = "HIGH"
        summary = "높은 보안 위험이 존재합니다. 조속한 대응을 권장합니다."
    elif total >= 30:
        level = "MEDIUM"
        summary = "보통 수준의 보안 위험입니다. 계획적 패치가 필요합니다."
    elif total >= 10:
        level = "LOW"
        summary = "낮은 수준의 보안 위험입니다. 모니터링을 유지하세요."
    else:
        level = "SAFE"
        summary = "심각한 보안 위험이 발견되지 않았습니다."

    return {
        "score": total,
        "level": level,
        "summary": summary,
        "breakdown": {
            "vulnerability_score": cve_score,
            "typosquatting_score": typo_score,
            "dependency_confusion_score": dep_score,
            "malware_score": malware_score,
        },
        "details": {
            "total_vulnerabilities": overview.get("total_vulnerabilities", 0),
            "critical_count": severity_count.get("CRITICAL", 0),
            "high_count": severity_count.get("HIGH", 0),
            "typosquatting_detected": typo_count,
            "dependency_confusion_detected": dep_count,
            "malware_flags": malware_count,
            "yara_hits": yara_hits,
        },
    }
