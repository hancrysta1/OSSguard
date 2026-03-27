"""AI-powered analysis endpoints."""

import json
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.utils.redis_client import redis_client
from app.utils.logging import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/ai", tags=["AI Analysis"])


class AiRequest(BaseModel):
    github_url: str


class AiCodeReviewRequest(BaseModel):
    github_url: str
    file_path: str = ""


class ChatRequest(BaseModel):
    github_url: str
    question: str
    history: list[dict] = []


class UpgradeRequest(BaseModel):
    github_url: str
    package_name: str
    current_version: str
    target_version: str


def _get_analysis_data(github_url: str) -> dict:
    """Helper to load cached analysis data."""
    repository_name = github_url.rstrip("/").split("/")[-1]
    cached = redis_client.get(f"dashboard:{repository_name}")
    if not cached:
        raise HTTPException(status_code=404, detail="Analysis not found. Run /store_analysis first.")
    return json.loads(cached)


@router.post("/summarize")
async def ai_summarize(req: AiRequest):
    """Generate AI-powered security summary for a repository analysis."""
    repository_name = req.github_url.rstrip("/").split("/")[-1]
    cached = redis_client.get(f"dashboard:{repository_name}")

    if not cached:
        raise HTTPException(status_code=404, detail="Analysis not found. Run /store_analysis first.")

    data = json.loads(cached)

    from app.services.ai.summarizer import generate_security_summary
    summary = await generate_security_summary(data)

    from app.services.ai.risk_scorer import calculate_risk_score
    risk = calculate_risk_score(data)

    return {
        "repository": data.get("repository", repository_name),
        "summary": summary,
        "risk_score": risk.get("score", 0),
        "risk_level": risk.get("level", "UNKNOWN"),
        "breakdown": risk.get("breakdown", {}),
    }


@router.post("/prioritize")
async def ai_prioritize(req: AiRequest):
    """AI-prioritize vulnerabilities by exploitability and impact."""
    repository_name = req.github_url.rstrip("/").split("/")[-1]
    cached = redis_client.get(f"dashboard:{repository_name}")

    if not cached:
        raise HTTPException(status_code=404, detail="Analysis not found. Run /store_analysis first.")

    data = json.loads(cached)
    vulnerabilities = data.get("vulnerabilities", data.get("top_vulnerabilities", []))

    from app.services.ai.vulnerability_prioritizer import prioritize_vulnerabilities
    prioritized = await prioritize_vulnerabilities(vulnerabilities)

    return {
        "repository": data.get("repository", repository_name),
        "total": len(prioritized),
        "prioritized_vulnerabilities": prioritized,
    }


@router.post("/risk-score")
async def ai_risk_score(req: AiRequest):
    """Get comprehensive risk score with breakdown."""
    repository_name = req.github_url.rstrip("/").split("/")[-1]
    cached = redis_client.get(f"dashboard:{repository_name}")

    if not cached:
        raise HTTPException(status_code=404, detail="Analysis not found. Run /store_analysis first.")

    data = json.loads(cached)

    from app.services.ai.risk_scorer import calculate_risk_score
    risk = calculate_risk_score(data)

    return {
        "repository": data.get("repository", repository_name),
        **risk,
    }


@router.post("/code-review")
async def ai_code_review(req: AiCodeReviewRequest):
    """AI-powered code review for security issues."""
    repository_name = req.github_url.rstrip("/").split("/")[-1]
    cached = redis_client.get(f"dashboard:{repository_name}")

    if not cached:
        raise HTTPException(status_code=404, detail="Analysis not found. Run /store_analysis first.")

    data = json.loads(cached)
    malware_results = data.get("malicious_code_analysis", [])

    from app.services.ai.code_analyzer import analyze_code_security
    review = await analyze_code_security(malware_results, repository_name)

    return {
        "repository": data.get("repository", repository_name),
        "review": review,
    }


@router.post("/full-report")
async def ai_full_report(req: AiRequest):
    """Generate a comprehensive AI security report combining all analyses."""
    repository_name = req.github_url.rstrip("/").split("/")[-1]
    cached = redis_client.get(f"dashboard:{repository_name}")

    if not cached:
        raise HTTPException(status_code=404, detail="Analysis not found. Run /store_analysis first.")

    data = json.loads(cached)

    from app.services.ai.summarizer import generate_security_summary
    from app.services.ai.vulnerability_prioritizer import prioritize_vulnerabilities
    from app.services.ai.risk_scorer import calculate_risk_score
    from app.services.ai.code_analyzer import analyze_code_security

    # Run AI analyses
    summary = await generate_security_summary(data)
    prioritized = await prioritize_vulnerabilities(
        data.get("vulnerabilities", data.get("top_vulnerabilities", []))
    )
    risk = calculate_risk_score(data)
    code_review = await analyze_code_security(
        data.get("malicious_code_analysis", []), repository_name
    )

    return {
        "repository": data.get("repository", repository_name),
        "analysis_date": data.get("analysis_date", ""),
        "ai_summary": summary,
        "risk_score": risk,
        "prioritized_vulnerabilities": prioritized[:10],
        "code_review": code_review,
        "security_overview": data.get("security_overview", {}),
    }


# === NEW: Fix Suggestions ===

@router.post("/fix-suggestions")
async def ai_fix_suggestions(req: AiRequest):
    """Generate automated fix commands and migration steps for each vulnerability."""
    data = _get_analysis_data(req.github_url)

    from app.services.ai.fix_advisor import generate_fix_suggestions
    fixes = await generate_fix_suggestions(data)

    return {
        "repository": data.get("repository", ""),
        "total_fixes": len(fixes),
        "fixes": fixes,
    }


# === NEW: License Compatibility ===

@router.post("/license-check")
async def ai_license_check(req: AiRequest):
    """Check license compatibility across all dependencies."""
    data = _get_analysis_data(req.github_url)

    from app.services.ai.license_checker import analyze_license_with_ai
    result = await analyze_license_with_ai(data)

    return {
        "repository": data.get("repository", ""),
        **result,
    }


# === NEW: Package Health ===

@router.post("/package-health")
async def ai_package_health(req: AiRequest):
    """Evaluate trustworthiness and maintenance status of all dependencies."""
    data = _get_analysis_data(req.github_url)
    packages = data.get("packages", [])

    from app.services.ai.package_health import evaluate_with_ai
    result = await evaluate_with_ai(packages, data)

    return {
        "repository": data.get("repository", ""),
        **result,
    }


# === NEW: Security Chatbot ===

@router.post("/chat")
async def ai_chat(req: ChatRequest):
    """Interactive Q&A about analysis results. Ask anything in natural language."""
    data = _get_analysis_data(req.github_url)

    from app.services.ai.chatbot import chat
    result = await chat(req.question, data, req.history)

    return {
        "repository": data.get("repository", ""),
        "question": req.question,
        **result,
    }


# === NEW: Upgrade Impact Analysis ===

@router.post("/upgrade-impact")
async def ai_upgrade_impact(req: UpgradeRequest):
    """Analyze what happens if you upgrade a package to a specific version."""
    data = _get_analysis_data(req.github_url)

    from app.services.ai.upgrade_analyzer import analyze_upgrade_impact
    result = await analyze_upgrade_impact(
        req.package_name, req.current_version, req.target_version, data
    )

    return {
        "repository": data.get("repository", ""),
        **result,
    }