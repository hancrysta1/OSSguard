import pytest
from app.services.typosquatting import detect_typosquatting
from app.services.dependency_confusion import check_dependency_confusion
from app.services.ai.risk_scorer import calculate_risk_score


def test_typosquatting_detection():
    is_typo, official = detect_typosquatting("reqeusts")
    assert is_typo is True
    assert official == "requests"


def test_typosquatting_no_match():
    is_typo, _ = detect_typosquatting("completely-different-pkg")
    assert is_typo is False


def test_risk_scorer():
    data = {
        "security_overview": {
            "severity_count": {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0},
        },
        "typosquatting_analysis": [{"typo_pkg": "reqeusts"}],
        "dependency_confusion_analysis": [],
        "malicious_code_analysis": [],
    }
    result = calculate_risk_score(data)
    assert result["total_score"] > 0
    assert result["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
