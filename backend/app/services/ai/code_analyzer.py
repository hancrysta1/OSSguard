"""AI-powered code analysis combining CodeBERT, entropy analysis, and pattern matching."""

import math
from collections import Counter
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)

_model = None
_tokenizer = None


def _load_model():
    """Load CodeBERT model lazily. Returns (model, tokenizer) or (None, None)."""
    global _model, _tokenizer
    if _model is not None:
        return _model, _tokenizer

    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch

        _tokenizer = AutoTokenizer.from_pretrained(settings.CODEBERT_MODEL)
        _model = AutoModelForSequenceClassification.from_pretrained(
            settings.CODEBERT_MODEL, num_labels=2
        )
        _model.eval()
        log.info("codebert_model_loaded", model=settings.CODEBERT_MODEL)
        return _model, _tokenizer
    except Exception as e:
        log.warning("codebert_load_failed", error=str(e))
        return None, None


def analyze_code_snippet(code: str) -> dict:
    """Classify a code snippet as malicious/benign using CodeBERT."""
    model, tokenizer = _load_model()
    if model is None:
        return {"malicious": False, "confidence": 0.0, "method": "unavailable"}

    try:
        import torch

        inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512, padding=True)
        with torch.no_grad():
            outputs = model(**inputs)

        probs = torch.softmax(outputs.logits, dim=-1)
        malicious_prob = probs[0][1].item()

        return {
            "malicious": malicious_prob >= settings.CODEBERT_CONFIDENCE_THRESHOLD,
            "confidence": round(malicious_prob, 4),
            "method": "codebert",
        }
    except Exception as e:
        log.error("codebert_analysis_failed", error=str(e))
        return {"malicious": False, "confidence": 0.0, "method": "error", "error": str(e)}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text. High entropy may indicate obfuscation."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def analyze_code_patterns(code: str) -> dict:
    """Combined analysis: pattern matching + entropy + CodeBERT.

    Returns a combined confidence score and detailed breakdown.
    """
    result = {
        "combined_score": 0.0,
        "pattern_score": 0.0,
        "entropy_score": 0.0,
        "ai_score": 0.0,
        "flags": [],
        "entropy": 0.0,
    }

    # 1. Pattern matching
    import re
    dangerous_patterns = {
        "exec": r"\bexec\s*\(",
        "eval": r"\beval\s*\(",
        "subprocess": r"\bsubprocess\.(Popen|call|run)\s*\(",
        "os.system": r"\bos\.system\s*\(",
        "base64_decode": r"\bbase64\.(b64decode|decodebytes)\s*\(",
        "pickle_load": r"\bpickle\.(loads?|Unpickler)\s*\(",
        "requests_post": r"\brequests\.(post|put)\s*\(",
        "socket_connect": r"\bsocket\..*connect\s*\(",
    }

    pattern_hits = 0
    for name, pattern in dangerous_patterns.items():
        if re.search(pattern, code):
            pattern_hits += 1
            result["flags"].append(name)

    result["pattern_score"] = min(1.0, pattern_hits * 0.2)

    # 2. Entropy analysis
    entropy = calculate_entropy(code)
    result["entropy"] = entropy
    # Normal code entropy is typically 4.0-5.5, obfuscated can be 6.0+
    if entropy > 6.0:
        result["entropy_score"] = 0.8
        result["flags"].append("high_entropy_obfuscation")
    elif entropy > 5.5:
        result["entropy_score"] = 0.4
    else:
        result["entropy_score"] = 0.0

    # 3. CodeBERT analysis (if available)
    ai_result = analyze_code_snippet(code)
    if ai_result.get("method") == "codebert":
        result["ai_score"] = ai_result["confidence"]
    else:
        result["ai_score"] = 0.0

    # Combined score: weighted average
    weights = {"pattern": 0.4, "entropy": 0.2, "ai": 0.4}
    if ai_result.get("method") != "codebert":
        # If no AI model, redistribute weight
        weights = {"pattern": 0.6, "entropy": 0.4, "ai": 0.0}

    result["combined_score"] = round(
        weights["pattern"] * result["pattern_score"]
        + weights["entropy"] * result["entropy_score"]
        + weights["ai"] * result["ai_score"],
        4,
    )

    return result


def analyze_flagged_files(malware_results: list[dict]) -> list[dict]:
    """Enhance malware detection results with AI analysis."""
    enhanced = []
    for entry in malware_results:
        result = entry.get("result", {})
        if not result or isinstance(entry.get("message"), str):
            enhanced.append(entry)
            continue

        has_flags = (
            result.get("dangerous_functions")
            or result.get("obfuscation_detected")
            or result.get("hardcoded_api_keys")
        )

        if has_flags:
            all_code = []
            for func_lines in result.get("dangerous_functions_lines", {}).values():
                for line_info in func_lines:
                    all_code.append(line_info.get("code", ""))

            if all_code:
                code_snippet = "\n".join(all_code[:10])
                entry["ai_analysis"] = analyze_code_patterns(code_snippet)

        enhanced.append(entry)
    return enhanced


async def analyze_code_security(malware_results: list[dict], repository_name: str) -> dict:
    """Comprehensive code security analysis combining all methods."""
    enhanced = analyze_flagged_files(malware_results)

    total_files = len(enhanced)
    flagged_files = [e for e in enhanced if e.get("ai_analysis", {}).get("combined_score", 0) > 0.3]
    high_risk = [e for e in enhanced if e.get("ai_analysis", {}).get("combined_score", 0) > 0.6]

    # Build summary
    all_flags = set()
    for e in enhanced:
        all_flags.update(e.get("ai_analysis", {}).get("flags", []))

    return {
        "repository": repository_name,
        "total_files_analyzed": total_files,
        "flagged_files": len(flagged_files),
        "high_risk_files": len(high_risk),
        "detected_patterns": sorted(all_flags),
        "details": [
            {
                "file": e.get("file", "unknown"),
                "combined_score": e.get("ai_analysis", {}).get("combined_score", 0),
                "flags": e.get("ai_analysis", {}).get("flags", []),
                "entropy": e.get("ai_analysis", {}).get("entropy", 0),
            }
            for e in flagged_files
        ],
    }
