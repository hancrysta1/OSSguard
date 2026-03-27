"""AI-powered security summary generation using Ollama with template fallback."""

import json
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


async def generate_security_summary(analysis_data: dict) -> str:
    """Generate a comprehensive Korean security summary.

    Uses Ollama LLM when available, falls back to template-based summary.
    """
    try:
        import ollama

        overview = analysis_data.get("security_overview", {})
        top_vulns = analysis_data.get("top_vulnerabilities", [])
        malware = analysis_data.get("malicious_code_analysis", [])
        typo = analysis_data.get("typosquatting_analysis", [])
        dep_conf = analysis_data.get("dependency_confusion_analysis", [])
        risk = analysis_data.get("risk_score", {})

        malware_count = len([
            m for m in malware
            if isinstance(m, dict) and m.get("result", {}).get("dangerous_functions")
        ])

        typo_count = len([t for t in typo if isinstance(t, dict) and "typo_pkg" in t])
        dep_count = len([d for d in dep_conf if isinstance(d, dict) and "risk" in d])

        prompt = f"""당신은 사이버보안 전문 분석가입니다. 다음 오픈소스 소프트웨어 보안 분석 결과를 한국어로 요약해주세요.

## 보안 분석 개요
- 저장소: {analysis_data.get('repository', 'N/A')}
- 분석 일시: {analysis_data.get('analysis_date', 'N/A')}
- 총 취약점 수: {overview.get('total_vulnerabilities', 0)}
- 심각도 분포: {json.dumps(overview.get('severity_count', {}), ensure_ascii=False)}
- 영향받는 패키지 수: {overview.get('affected_packages_count', 0)}
- 업데이트 권장 패키지 수: {overview.get('recommended_updates_count', 0)}

## 주요 취약점 (Top 3)
{json.dumps(top_vulns[:3], indent=2, ensure_ascii=False)}

## 공급망 보안 위협
- 악성 코드 의심 파일: {malware_count}개
- Typosquatting 의심: {typo_count}건
- Dependency Confusion 위험: {dep_count}건

## 요청사항
1. 전체 보안 상태를 2-3문장으로 평가
2. 가장 시급히 대응해야 할 위험 요소 2-3가지
3. 구체적인 개선 권장사항 3가지
4. 공급망 공격 위험도에 대한 의견

간결하고 실무적인 보고서 형식으로 작성해주세요."""

        response = ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3, "num_predict": 1024},
        )

        summary = response["message"]["content"]
        log.info("ai_summary_generated", length=len(summary))
        return summary

    except ImportError:
        log.warning("ollama_not_installed_using_template")
        return _template_summary(analysis_data)
    except Exception as e:
        log.error("ai_summary_failed", error=str(e))
        return _template_summary(analysis_data)


def _template_summary(analysis_data: dict) -> str:
    """Template-based fallback summary when AI is unavailable."""
    overview = analysis_data.get("security_overview", {})
    total_vulns = overview.get("total_vulnerabilities", 0)
    severity = overview.get("severity_count", {})
    critical = severity.get("CRITICAL", 0)
    high = severity.get("HIGH", 0)
    affected = overview.get("affected_packages_count", 0)
    repo = analysis_data.get("repository", "Unknown")

    malware = analysis_data.get("malicious_code_analysis", [])
    malware_count = len([
        m for m in malware
        if isinstance(m, dict) and m.get("result", {}).get("dangerous_functions")
    ])

    typo = analysis_data.get("typosquatting_analysis", [])
    typo_count = len([t for t in typo if isinstance(t, dict) and "typo_pkg" in t])

    # Risk level determination
    if critical > 0 or malware_count > 2:
        risk_text = "심각한 보안 위험이 감지되었습니다"
        action = "즉시 대응이 필요합니다"
    elif high > 0 or total_vulns > 5:
        risk_text = "높은 수준의 보안 위험이 존재합니다"
        action = "조속한 대응을 권장합니다"
    elif total_vulns > 0:
        risk_text = "일부 보안 취약점이 발견되었습니다"
        action = "순차적 패치를 권장합니다"
    else:
        risk_text = "심각한 보안 위험은 발견되지 않았습니다"
        action = "정기적인 모니터링을 유지하세요"

    lines = [
        f"## {repo} 보안 분석 보고서",
        "",
        f"### 전체 평가",
        f"{risk_text}. 총 {total_vulns}개의 취약점이 발견되었으며, "
        f"이 중 CRITICAL {critical}개, HIGH {high}개입니다. {action}.",
        "",
        f"### 주요 위험 요소",
        f"- 취약한 패키지: {affected}개의 패키지에서 보안 취약점 발견",
    ]

    if malware_count > 0:
        lines.append(f"- 악성 코드 의심: {malware_count}개 파일에서 위험한 함수 호출 패턴 탐지")
    if typo_count > 0:
        lines.append(f"- Typosquatting 의심: {typo_count}건의 패키지명 유사도 경고")

    lines.extend([
        "",
        f"### 권장 조치사항",
        f"1. CRITICAL/HIGH 심각도 취약점을 가진 패키지를 최신 버전으로 업데이트",
        f"2. 악성 코드 의심 파일에 대한 수동 코드 리뷰 수행",
        f"3. 의존성 목록 검증 및 불필요한 패키지 제거",
    ])

    top_vulns = analysis_data.get("top_vulnerabilities", [])
    if top_vulns:
        lines.extend(["", "### 최우선 대응 취약점"])
        for v in top_vulns[:3]:
            lines.append(
                f"- **{v.get('cve_id', 'N/A')}** ({v.get('severity', 'N/A')}): "
                f"{v.get('package', 'N/A')} - {v.get('description', 'N/A')[:100]}"
            )

    return "\n".join(lines)


async def generate_security_report(analysis_data: dict) -> dict:
    """Generate a structured security report combining AI summary with data."""
    summary = await generate_security_summary(analysis_data)
    overview = analysis_data.get("security_overview", {})

    from app.services.ai.risk_scorer import calculate_risk_score
    risk = calculate_risk_score(analysis_data)

    return {
        "summary": summary,
        "risk_score": risk,
        "overview": overview,
        "repository": analysis_data.get("repository", ""),
        "analysis_date": analysis_data.get("analysis_date", ""),
        "top_vulnerabilities": analysis_data.get("top_vulnerabilities", [])[:5],
        "recommendations": _generate_recommendations(analysis_data),
    }


def _generate_recommendations(data: dict) -> list[str]:
    """Generate actionable recommendations based on analysis data."""
    recs = []
    overview = data.get("security_overview", {})
    severity = overview.get("severity_count", {})

    if severity.get("CRITICAL", 0) > 0:
        recs.append("CRITICAL 취약점이 존재합니다. 즉시 영향받는 패키지를 업데이트하세요.")
    if severity.get("HIGH", 0) > 0:
        recs.append("HIGH 심각도 취약점에 대한 패치 계획을 수립하세요.")

    malware = data.get("malicious_code_analysis", [])
    for m in malware:
        if isinstance(m, dict) and m.get("result", {}).get("dangerous_functions"):
            recs.append("악성 코드 의심 파일이 발견되었습니다. 수동 코드 리뷰를 수행하세요.")
            break

    typo = data.get("typosquatting_analysis", [])
    if any(isinstance(t, dict) and "typo_pkg" in t for t in typo):
        recs.append("Typosquatting 의심 패키지를 확인하고 정식 패키지로 교체하세요.")

    dep = data.get("dependency_confusion_analysis", [])
    if any(isinstance(d, dict) and "risk" in d for d in dep):
        recs.append("내부 패키지에 대한 Dependency Confusion 위험을 검토하세요.")

    if overview.get("recommended_updates_count", 0) > 0:
        recs.append(f"{overview['recommended_updates_count']}개 패키지의 보안 업데이트를 적용하세요.")

    if not recs:
        recs.append("현재 심각한 보안 문제는 발견되지 않았습니다. 정기적인 스캔을 유지하세요.")

    return recs
