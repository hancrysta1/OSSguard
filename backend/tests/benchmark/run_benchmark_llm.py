"""
OSSGuard LLM SAST 벤치마크 - Before/After 비교
================================================
기존 키워드 탐지 vs LLM 기반 2차 판단의 성능을 비교합니다.

사용법:
    cd ossguard/backend
    python3 -m tests.benchmark.run_benchmark_llm

필요: Ollama 실행 중 (ollama serve)
"""

import asyncio
import json
import re
import math
import time
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"
BENIGN_DIR = FIXTURES_DIR / "benign"


# ═══════════════════════════════════════════════════════════════
#  Before: 기존 키워드 탐지 (동일 로직)
# ═══════════════════════════════════════════════════════════════

DANGEROUS_FUNCS = ["exec", "eval", "subprocess.Popen", "os.system"]
DANGEROUS_FUNC_PATTERNS = {re.compile(rf"\b{re.escape(f)}\b"): f for f in DANGEROUS_FUNCS}
OBFUSCATION_KEYWORDS = ["base64", "zlib"]
API_KEY_PATTERN = re.compile(r"(API_KEY|apikey|secret_key|SECRET)", re.IGNORECASE)


def detect_pattern_only(file_path: str) -> tuple:
    """Before: 키워드만 보고 판단"""
    results = {"dangerous_functions": [], "obfuscation": False, "api_keys": False}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        for line in content.splitlines():
            stripped = line.strip()
            for pat, func in DANGEROUS_FUNC_PATTERNS.items():
                if pat.search(stripped) and func not in results["dangerous_functions"]:
                    results["dangerous_functions"].append(func)
            for kw in OBFUSCATION_KEYWORDS:
                if kw in stripped:
                    results["obfuscation"] = True
            if API_KEY_PATTERN.search(stripped):
                results["api_keys"] = True
    except Exception:
        pass
    detected = bool(results["dangerous_functions"] or results["obfuscation"] or results["api_keys"])
    return detected, results


# ═══════════════════════════════════════════════════════════════
#  After: LLM 2차 판단 추가
# ═══════════════════════════════════════════════════════════════

DANGEROUS_CODE_PATTERNS = {
    "exec": r"\bexec\s*\(",
    "eval": r"\beval\s*\(",
    "subprocess": r"\bsubprocess\.(Popen|call|run)\s*\(",
    "os.system": r"\bos\.system\s*\(",
    "base64_decode": r"\bbase64\.(b64decode|decodebytes)\s*\(",
    "pickle_load": r"\bpickle\.(loads?|Unpickler)\s*\(",
    "requests_post": r"\brequests\.(post|put)\s*\(",
    "socket_connect": r"\bsocket\..*connect\s*\(",
}

LLM_PROMPT = """당신은 코드 보안 분석가입니다. 아래 코드에서 위험 키워드가 탐지되었습니다.

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


async def _ask_llm(code: str, flags: list) -> dict:
    """Ollama에 코드 의도 판단 요청"""
    try:
        import ollama

        prompt = LLM_PROMPT.format(flags=", ".join(flags), code=code[:2000])
        response = ollama.chat(
            model="llama3.2:1b",
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": 256},
        )
        content = response["message"]["content"].strip()
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            return {"verdict": result.get("verdict", "unknown"), "reason": result.get("reason", "")}
        return {"verdict": "unknown", "reason": "파싱 실패"}
    except Exception as e:
        return {"verdict": "unknown", "reason": str(e)}


async def detect_with_llm(file_path: str) -> tuple:
    """After: 키워드 1차 → LLM 2차 판단"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception:
        return False, {"error": "read failed"}

    # 1차: 키워드 스캔
    flags = [name for name, pat in DANGEROUS_CODE_PATTERNS.items() if re.search(pat, code)]

    # 난독화 키워드
    has_obfuscation = any(kw in code for kw in OBFUSCATION_KEYWORDS)
    has_api_keys = bool(API_KEY_PATTERN.search(code))

    if has_obfuscation:
        flags.append("obfuscation")
    if has_api_keys:
        flags.append("hardcoded_secrets")

    # 키워드 없으면 → 통과
    if not flags:
        return False, {"flags": [], "stage": "pattern_pass"}

    # 2차: LLM 판단
    llm = await _ask_llm(code, flags)
    verdict = llm["verdict"].lower()

    if verdict == "safe":
        return False, {"flags": flags, "llm_verdict": "safe", "llm_reason": llm["reason"], "stage": "llm_cleared"}
    elif verdict == "malicious":
        return True, {"flags": flags, "llm_verdict": "malicious", "llm_reason": llm["reason"], "stage": "llm_confirmed"}
    else:
        # LLM 판단 불가 → 보수적으로 키워드 결과 유지
        return True, {"flags": flags, "llm_verdict": "unknown", "llm_reason": llm["reason"], "stage": "fallback"}


# ═══════════════════════════════════════════════════════════════
#  벤치마크 실행
# ═══════════════════════════════════════════════════════════════

@dataclass
class Result:
    tp: int = 0; fp: int = 0; tn: int = 0; fn: int = 0
    details: list = field(default_factory=list)

    @property
    def precision(self): return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
    @property
    def recall(self): return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
    @property
    def f1(self):
        p, r = self.precision, self.recall
        return 2*p*r/(p+r) if (p+r) else 0.0
    @property
    def fp_rate(self): return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0
    @property
    def accuracy(self):
        t = self.tp+self.fp+self.tn+self.fn
        return (self.tp+self.tn)/t if t else 0.0


def run_sync_benchmark(detect_func) -> Result:
    """동기 탐지 함수용 벤치마크"""
    r = Result()
    for fp in sorted(MALICIOUS_DIR.glob("*.py")):
        detected, _ = detect_func(str(fp))
        if detected: r.tp += 1; status = "TP"
        else: r.fn += 1; status = "FN"
        r.details.append({"file": fp.name, "label": "malicious", "detected": detected, "status": status})
    for fp in sorted(BENIGN_DIR.glob("*.py")):
        detected, _ = detect_func(str(fp))
        if detected: r.fp += 1; status = "FP"
        else: r.tn += 1; status = "TN"
        r.details.append({"file": fp.name, "label": "benign", "detected": detected, "status": status})
    return r


async def run_async_benchmark(detect_func) -> Result:
    """비동기 탐지 함수용 벤치마크 (LLM)"""
    r = Result()
    for fp in sorted(MALICIOUS_DIR.glob("*.py")):
        detected, detail = await detect_func(str(fp))
        if detected: r.tp += 1; status = "TP"
        else: r.fn += 1; status = "FN"
        r.details.append({
            "file": fp.name, "label": "malicious", "detected": detected, "status": status,
            "llm_verdict": detail.get("llm_verdict", ""), "llm_reason": detail.get("llm_reason", ""),
        })
    for fp in sorted(BENIGN_DIR.glob("*.py")):
        detected, detail = await detect_func(str(fp))
        if detected: r.fp += 1; status = "FP"
        else: r.tn += 1; status = "TN"
        r.details.append({
            "file": fp.name, "label": "benign", "detected": detected, "status": status,
            "llm_verdict": detail.get("llm_verdict", ""), "llm_reason": detail.get("llm_reason", ""),
        })
    return r


def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_metrics(r: Result):
    print(f"  TP (정탐): {r.tp}  |  FP (오탐): {r.fp}")
    print(f"  FN (미탐): {r.fn}  |  TN (정상): {r.tn}")
    print(f"  Precision: {r.precision:.1%}  |  Recall: {r.recall:.1%}  |  F1: {r.f1:.1%}")
    print(f"  FP Rate: {r.fp_rate:.1%}  |  Accuracy: {r.accuracy:.1%}")


def print_errors(r: Result):
    errors = [d for d in r.details if d["status"] not in ("TP", "TN")]
    if errors:
        print(f"\n  오분류:")
        for d in errors:
            reason = f" → LLM: {d.get('llm_reason', '')}" if d.get("llm_reason") else ""
            print(f"    [{d['status']}] {d['file']}{reason}")
    else:
        print(f"\n  모든 샘플 정확히 분류됨!")


async def main():
    mal_count = len(list(MALICIOUS_DIR.glob("*.py")))
    ben_count = len(list(BENIGN_DIR.glob("*.py")))

    print(f"\n{'='*60}")
    print(f"  OSSGuard SAST 벤치마크: Before vs After (LLM)")
    print(f"  샘플: 악성 {mal_count}개 / 정상 {ben_count}개")
    print(f"{'='*60}")

    # ─── Before: 키워드 단독 ───
    print_header("Before: 키워드 탐지 단독")
    t1 = time.time()
    r_before = run_sync_benchmark(detect_pattern_only)
    t1 = time.time() - t1
    print_metrics(r_before)
    print_errors(r_before)
    print(f"  소요 시간: {t1:.2f}초")

    # ─── After: 키워드 + LLM ───
    print_header("After: 키워드 1차 → LLM 2차 판단")
    t2 = time.time()
    r_after = await run_async_benchmark(detect_with_llm)
    t2 = time.time() - t2
    print_metrics(r_after)
    print_errors(r_after)
    print(f"  소요 시간: {t2:.2f}초")

    # ─── 비교 ───
    print_header("Before vs After 비교")
    print(f"  {'지표':<20} {'Before':>10} {'After':>10} {'변화':>10}")
    print(f"  {'-'*50}")
    metrics = [
        ("Precision", r_before.precision, r_after.precision),
        ("Recall", r_before.recall, r_after.recall),
        ("F1 Score", r_before.f1, r_after.f1),
        ("FP Rate", r_before.fp_rate, r_after.fp_rate),
        ("Accuracy", r_before.accuracy, r_after.accuracy),
    ]
    for name, before, after in metrics:
        diff = after - before
        arrow = "↑" if diff > 0 else "↓" if diff < 0 else "→"
        # FP Rate는 낮아져야 좋음
        if name == "FP Rate":
            arrow = "↓ (개선)" if diff < 0 else "↑ (악화)" if diff > 0 else "→"
        print(f"  {name:<20} {before:>9.1%} {after:>9.1%} {arrow:>10}")

    # ─── LLM 판단 상세 ───
    print_header("LLM 판단 상세")
    for d in r_after.details:
        if d.get("llm_verdict"):
            icon = "✓" if d["status"] in ("TP", "TN") else "✗"
            print(f"  {icon} [{d['status']}] {d['file']:<30} LLM: {d['llm_verdict']:<10} {d.get('llm_reason', '')[:50]}")

    # ─── JSON 저장 ───
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "samples": {"malicious": mal_count, "benign": ben_count},
        "before": {
            "tp": r_before.tp, "fp": r_before.fp, "tn": r_before.tn, "fn": r_before.fn,
            "precision": round(r_before.precision, 4), "recall": round(r_before.recall, 4),
            "f1": round(r_before.f1, 4), "fp_rate": round(r_before.fp_rate, 4),
        },
        "after": {
            "tp": r_after.tp, "fp": r_after.fp, "tn": r_after.tn, "fn": r_after.fn,
            "precision": round(r_after.precision, 4), "recall": round(r_after.recall, 4),
            "f1": round(r_after.f1, 4), "fp_rate": round(r_after.fp_rate, 4),
            "details": r_after.details,
        },
    }
    report_path = Path(__file__).resolve().parent / "benchmark_llm_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  리포트 저장: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())
