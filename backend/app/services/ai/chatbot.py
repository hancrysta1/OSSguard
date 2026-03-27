"""Interactive security chatbot - natural language Q&A about analysis results."""

import json
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


async def chat(question: str, analysis_data: dict, history: list[dict] = None) -> dict:
    """Answer security questions about analysis results in natural language.

    Supports questions like:
    - "RCE 취약점만 보여줘"
    - "가장 위험한 패키지는?"
    - "이 CVE 어떻게 고쳐?"
    - "GPL 라이선스 쓰는 패키지 있어?"
    - "전체 보안 상태 요약해줘"
    """
    # Build context from analysis data
    context = _build_context(analysis_data)

    # Try AI response
    ai_response = await _ai_chat(question, context, history or [])
    if ai_response:
        return {
            "answer": ai_response,
            "source": "ai",
            "related_data": _extract_related_data(question, analysis_data),
        }

    # Fallback: keyword-based response
    fallback = _keyword_response(question, analysis_data)
    return {
        "answer": fallback,
        "source": "keyword",
        "related_data": _extract_related_data(question, analysis_data),
    }


async def _ai_chat(question: str, context: str, history: list[dict]) -> str | None:
    """Use Ollama for intelligent Q&A."""
    try:
        import ollama

        system_prompt = f"""당신은 오픈소스 보안 분석 전문 어시스턴트입니다.
사용자의 질문에 다음 분석 데이터를 기반으로 정확하고 실용적인 한국어 답변을 해주세요.
데이터에 없는 내용은 추측하지 마세요.

분석 데이터:
{context}"""

        messages = [{"role": "system", "content": system_prompt}]

        # Add conversation history (last 5 turns)
        for h in history[-5:]:
            messages.append({"role": h.get("role", "user"), "content": h.get("content", "")})

        messages.append({"role": "user", "content": question})

        response = ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=messages,
            options={"temperature": 0.3, "num_predict": 1024},
        )
        return response["message"]["content"]

    except Exception as e:
        log.warning("chatbot_ai_failed", error=str(e))
        return None


def _build_context(data: dict) -> str:
    """Build a concise context string from analysis data."""
    overview = data.get("security_overview", {})
    severity = overview.get("severity_count", {})
    top_vulns = data.get("top_vulnerabilities", [])
    packages = data.get("packages", [])
    malware = data.get("malicious_code_analysis", [])
    typo = data.get("typosquatting_analysis", [])
    risk = data.get("risk_score", {})

    lines = [
        f"저장소: {data.get('repository', 'N/A')}",
        f"분석 일시: {data.get('analysis_date', 'N/A')}",
        f"총 취약점: {overview.get('total_vulnerabilities', 0)}",
        f"심각도: CRITICAL={severity.get('CRITICAL', 0)}, HIGH={severity.get('HIGH', 0)}, MEDIUM={severity.get('MEDIUM', 0)}, LOW={severity.get('LOW', 0)}",
        f"총 패키지: {len(packages)}개",
        f"업데이트 권장: {overview.get('recommended_updates_count', 0)}개",
    ]

    if top_vulns:
        lines.append("\n주요 취약점:")
        for v in top_vulns[:5]:
            lines.append(f"- {v.get('cve_id', 'N/A')} ({v.get('severity', 'N/A')}): {v.get('package', 'N/A')} - {v.get('description', '')[:100]}")

    malware_count = len([m for m in malware if isinstance(m, dict) and m.get("result", {}).get("dangerous_functions")])
    if malware_count:
        lines.append(f"\n악성 코드 의심 파일: {malware_count}개")

    typo_count = len([t for t in typo if isinstance(t, dict) and "typo_pkg" in t])
    if typo_count:
        lines.append(f"타이포스쿼팅 의심: {typo_count}건")

    if isinstance(risk, dict) and "score" in risk:
        lines.append(f"\n리스크 점수: {risk['score']}/100 ({risk.get('level', 'N/A')})")

    return "\n".join(lines)


def _keyword_response(question: str, data: dict) -> str:
    """Keyword-based fallback when AI is unavailable."""
    q = question.lower()

    if any(kw in q for kw in ["rce", "원격", "코드 실행"]):
        vulns = [v for v in data.get("top_vulnerabilities", [])
                 if "remote code" in v.get("description", "").lower() or "rce" in v.get("description", "").lower()]
        if vulns:
            return "RCE 관련 취약점:\n" + "\n".join(
                f"- {v['cve_id']} ({v.get('severity', 'N/A')}): {v.get('package', 'N/A')}" for v in vulns
            )
        return "RCE 관련 취약점은 발견되지 않았습니다."

    if any(kw in q for kw in ["위험", "가장", "심각", "critical"]):
        overview = data.get("security_overview", {})
        severity = overview.get("severity_count", {})
        return (
            f"보안 현황: 총 {overview.get('total_vulnerabilities', 0)}개 취약점\n"
            f"CRITICAL: {severity.get('CRITICAL', 0)}개, HIGH: {severity.get('HIGH', 0)}개\n"
            f"가장 위험한 패키지부터 업데이트하세요."
        )

    if any(kw in q for kw in ["라이선스", "gpl", "mit", "license"]):
        packages = data.get("packages", [])
        licenses = {}
        for p in packages:
            lic = p.get("licenseConcluded", p.get("license", "Unknown"))
            licenses[lic] = licenses.get(lic, 0) + 1
        return "사용 중인 라이선스:\n" + "\n".join(f"- {k}: {v}개" for k, v in sorted(licenses.items(), key=lambda x: -x[1])[:10])

    if any(kw in q for kw in ["요약", "전체", "상태", "overview"]):
        overview = data.get("security_overview", {})
        return (
            f"저장소: {data.get('repository', 'N/A')}\n"
            f"총 취약점: {overview.get('total_vulnerabilities', 0)}개\n"
            f"영향받는 패키지: {overview.get('affected_packages_count', 0)}개\n"
            f"업데이트 필요: {overview.get('recommended_updates_count', 0)}개"
        )

    if any(kw in q for kw in ["고쳐", "수정", "fix", "업데이트", "패치"]):
        updates = data.get("update_recommendations", {})
        if isinstance(updates, dict) and updates:
            lines = ["업데이트 권장 패키지:"]
            for pkg, details in list(updates.items())[:5]:
                if isinstance(details, dict):
                    versions = details.get("recommended_versions", [])
                    lines.append(f"- {pkg}: {', '.join(versions) if versions else 'N/A'}")
            return "\n".join(lines)
        return "현재 업데이트가 필요한 패키지 정보가 없습니다."

    return "죄송합니다, 질문을 이해하지 못했습니다. 취약점, 라이선스, 보안 요약 등에 대해 질문해주세요."


def _extract_related_data(question: str, data: dict) -> dict | None:
    """Extract data relevant to the question for frontend display."""
    q = question.lower()

    if any(kw in q for kw in ["취약점", "cve", "vulnerability"]):
        return {"type": "vulnerabilities", "data": data.get("top_vulnerabilities", [])[:5]}

    if any(kw in q for kw in ["패키지", "sbom", "package"]):
        return {"type": "packages", "data": data.get("packages", [])[:10]}

    if any(kw in q for kw in ["악성", "malware", "탐지"]):
        return {"type": "malware", "data": data.get("malicious_code_analysis", [])[:5]}

    return None
