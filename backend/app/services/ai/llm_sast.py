"""LLM 기반 SAST 분석 - 코드의 '의도'를 판단하여 오탐을 줄이고 탐지 정확도를 높임.

기존 키워드 탐지가 잡은 코드를 LLM에 넘겨서:
- "이 base64는 이미지 처리용이다 → 정상"
- "이 base64는 페이로드 복호화 목적이다 → 위험"
이런 식으로 2차 판단을 수행합니다.
"""

import json
import re
import math
from collections import Counter
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)

# ─── 기존 패턴 탐지 (1차 필터) ─────────────────────────────

DANGEROUS_PATTERNS = {
    "exec": r"\bexec\s*\(",
    "eval": r"\beval\s*\(",
    "subprocess": r"\bsubprocess\.(Popen|call|run)\s*\(",
    "os.system": r"\bos\.system\s*\(",
    "base64_decode": r"\bbase64\.(b64decode|decodebytes)\s*\(",
    "pickle_load": r"\bpickle\.(loads?|Unpickler)\s*\(",
    "requests_post": r"\brequests\.(post|put)\s*\(",
    "socket_connect": r"\bsocket\..*connect\s*\(",
}


def _pattern_scan(code: str) -> list[str]:
    """키워드 기반 1차 필터. 위험 패턴 이름 리스트 반환."""
    return [name for name, pat in DANGEROUS_PATTERNS.items() if re.search(pat, code)]


def _calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return round(-sum(
        (c / length) * math.log2(c / length) for c in counter.values()
    ), 4)


# ─── LLM 기반 의도 분석 (2차 판단) ──────────────────────────

LLM_PROMPT_TEMPLATE = """당신은 코드 보안 분석가입니다. 아래 코드에서 위험 키워드가 탐지되었습니다.

## 탐지된 키워드
{flags}

## 분석 대상 코드
```
{code}
```

## 판단 기준
- 해당 키워드가 **정상적인 목적**(이미지 처리, git 명령, 테스트, API 호출 등)으로 사용되었으면 "safe"
- **악의적인 목적**(데이터 탈취, 원격 코드 실행, 난독화된 페이로드 복호화, 리버스 쉘 등)이면 "malicious"

## 응답 형식 (JSON만 반환)
{{"verdict": "safe" 또는 "malicious", "reason": "한국어로 1문장 판단 근거"}}"""


async def _llm_judge(code: str, flags: list[str]) -> dict:
    """Ollama LLM으로 코드의 의도를 판단."""
    try:
        import ollama

        prompt = LLM_PROMPT_TEMPLATE.format(
            flags=", ".join(flags),
            code=code[:2000],  # 토큰 제한
        )

        response = ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": 256},
        )

        content = response["message"]["content"].strip()

        # JSON 추출 (마크다운 코드블록 안에 있을 수 있음)
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            verdict = result.get("verdict", "").lower()
            reason = result.get("reason", "")
            log.info("llm_sast_judged", verdict=verdict, reason=reason[:50])
            return {
                "verdict": verdict,
                "reason": reason,
                "method": "llm",
            }

        log.warning("llm_sast_parse_failed", content=content[:100])
        return {"verdict": "unknown", "reason": "LLM 응답 파싱 실패", "method": "llm_error"}

    except ImportError:
        log.warning("ollama_not_installed")
        return {"verdict": "unknown", "reason": "Ollama 미설치", "method": "unavailable"}
    except Exception as e:
        log.error("llm_sast_failed", error=str(e))
        return {"verdict": "unknown", "reason": str(e), "method": "error"}


# ─── 통합 분석 파이프라인 ────────────────────────────────────

async def analyze_with_llm(code: str) -> dict:
    """키워드 1차 필터 → LLM 2차 판단 통합 분석.

    Returns:
        {
            "detected": bool,          # 최종 악성 판정
            "flags": list[str],        # 탐지된 키워드
            "entropy": float,
            "llm_verdict": str,        # "safe" | "malicious" | "unknown"
            "llm_reason": str,         # LLM 판단 근거
            "method": str,             # "llm" | "pattern_only" | "error"
            "stage": str,              # 어느 단계에서 판정났는지
        }
    """
    result = {
        "detected": False,
        "flags": [],
        "entropy": 0.0,
        "llm_verdict": "",
        "llm_reason": "",
        "method": "pattern_only",
        "stage": "",
    }

    # 1차: 키워드 패턴 스캔
    flags = _pattern_scan(code)
    entropy = _calculate_entropy(code)
    result["flags"] = flags
    result["entropy"] = entropy

    # 키워드가 없으면 → 정상 판정 (패턴 탐지 통과)
    if not flags and entropy < 6.0:
        result["stage"] = "pattern_pass"
        return result

    # 엔트로피만 높고 키워드 없으면 → 난독화 의심만 표시
    if not flags and entropy >= 6.0:
        result["flags"].append("high_entropy")
        result["detected"] = True
        result["stage"] = "entropy_flagged"
        return result

    # 2차: LLM으로 코드 의도 판단
    llm_result = await _llm_judge(code, flags)
    result["llm_verdict"] = llm_result["verdict"]
    result["llm_reason"] = llm_result["reason"]
    result["method"] = llm_result["method"]

    if llm_result["verdict"] == "safe":
        # LLM이 정상이라고 판단 → 오탐 제거
        result["detected"] = False
        result["stage"] = "llm_cleared"
    elif llm_result["verdict"] == "malicious":
        # LLM이 악성이라고 판단 → 위험 확정
        result["detected"] = True
        result["stage"] = "llm_confirmed"
    else:
        # LLM 판단 불가 → 키워드 탐지 결과 그대로 유지 (보수적)
        result["detected"] = True
        result["stage"] = "llm_unavailable_fallback"

    return result


async def analyze_file_with_llm(file_path: str) -> dict:
    """파일 경로를 받아서 LLM SAST 분석 수행."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
        result = await analyze_with_llm(code)
        result["file"] = file_path
        return result
    except Exception as e:
        return {
            "file": file_path,
            "detected": False,
            "flags": [],
            "error": str(e),
            "method": "error",
            "stage": "read_error",
        }
