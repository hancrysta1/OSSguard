"""
OSSGuard Security Detection Benchmark
======================================
악성/정상 샘플 파일에 대해 탐지 성능을 측정합니다.
외부 의존성(yara, redis 등) 없이 standalone 실행 가능합니다.

측정 지표:
- Precision (정밀도): 탐지된 것 중 실제 악성인 비율
- Recall (재현율): 실제 악성 중 탐지된 비율
- F1 Score: Precision과 Recall의 조화평균
- False Positive Rate: 정상 파일을 악성으로 잘못 탐지한 비율

사용법:
    cd ossguard/backend
    python3 tests/benchmark/run_benchmark.py
"""

import re
import math
import json
import time
import difflib
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"
BENIGN_DIR = FIXTURES_DIR / "benign"


# ═══════════════════════════════════════════════════════════════
#  탐지 엔진 (standalone - 외부 의존성 없음)
# ═══════════════════════════════════════════════════════════════

# ─── 1. 패턴 매칭 (malware.py 동일 로직) ─────────────────────

DANGEROUS_FUNCS = ["exec", "eval", "subprocess.Popen", "os.system"]
DANGEROUS_FUNC_PATTERNS = {re.compile(rf"\b{re.escape(func)}\b"): func for func in DANGEROUS_FUNCS}
OBFUSCATION_KEYWORDS = ["base64", "zlib"]
API_KEY_PATTERN = re.compile(r"(API_KEY|apikey|secret_key|SECRET)", re.IGNORECASE)


def detect_malicious_code(file_path: str) -> dict:
    """패턴 매칭 기반 악성코드 탐지 (malware.py 동일 로직 재현)"""
    results = {
        "dangerous_functions": [],
        "obfuscation_detected": False,
        "hardcoded_api_keys": False,
        "suspicious_filename": False,
        "details": [],
    }

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        results["error"] = str(e)
        return results

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        for pattern, func in DANGEROUS_FUNC_PATTERNS.items():
            if pattern.search(stripped):
                if func not in results["dangerous_functions"]:
                    results["dangerous_functions"].append(func)
                results["details"].append(f"L{idx}: {func} → {stripped[:80]}")

        for keyword in OBFUSCATION_KEYWORDS:
            if keyword in stripped:
                results["obfuscation_detected"] = True

        if API_KEY_PATTERN.search(stripped):
            results["hardcoded_api_keys"] = True

    suspicious_files = ["setup.py", "install.py", "bootstrap.py", "update.py", "upgrade.py"]
    for pattern in suspicious_files:
        if pattern in file_path.lower():
            results["suspicious_filename"] = True

    return results


# ─── 2. 앙상블 분석 (code_analyzer.py 동일 로직) ─────────────

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


def calculate_entropy(text: str) -> float:
    """Shannon 엔트로피 계산"""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )


def analyze_code_patterns(code: str) -> dict:
    """앙상블 분석: 패턴 + 엔트로피 (CodeBERT 없이)"""
    result = {
        "combined_score": 0.0,
        "pattern_score": 0.0,
        "entropy_score": 0.0,
        "flags": [],
        "entropy": 0.0,
    }

    # 패턴 매칭
    pattern_hits = 0
    for name, pattern in DANGEROUS_CODE_PATTERNS.items():
        if re.search(pattern, code):
            pattern_hits += 1
            result["flags"].append(name)
    result["pattern_score"] = min(1.0, pattern_hits * 0.2)

    # 엔트로피
    entropy = calculate_entropy(code)
    result["entropy"] = round(entropy, 4)
    if entropy > 6.0:
        result["entropy_score"] = 0.8
        result["flags"].append("high_entropy")
    elif entropy > 5.5:
        result["entropy_score"] = 0.4

    # CodeBERT 없이: pattern 0.6 + entropy 0.4
    result["combined_score"] = round(
        0.6 * result["pattern_score"] + 0.4 * result["entropy_score"], 4
    )

    return result


# ─── 3. 타이포스쿼팅 (typosquatting.py 동일 로직) ────────────

OFFICIAL_PACKAGES = {
    "requests", "numpy", "pandas", "express", "lodash",
    "flask", "django", "scipy", "matplotlib", "pillow",
}
THRESHOLD = 0.9


def detect_typosquatting(package_name: str) -> tuple:
    if package_name.lower() in OFFICIAL_PACKAGES:
        return False, None
    for official in OFFICIAL_PACKAGES:
        similarity = difflib.SequenceMatcher(None, package_name.lower(), official.lower()).ratio()
        if similarity >= THRESHOLD:
            return True, official
    return False, None


# ═══════════════════════════════════════════════════════════════
#  벤치마크 프레임워크
# ═══════════════════════════════════════════════════════════════

@dataclass
class BenchmarkResult:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    details: list = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0


# ─── 탐지 판정 함수 ──────────────────────────────────────────

def is_detected_by_pattern(file_path: str) -> tuple:
    """패턴 매칭 단독 판정"""
    result = detect_malicious_code(file_path)
    detected = bool(
        result.get("dangerous_functions")
        or result.get("obfuscation_detected")
        or result.get("hardcoded_api_keys")
    )
    return detected, result


def is_detected_by_ensemble(file_path: str) -> tuple:
    """앙상블 분석 판정 (threshold: 0.3)"""
    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()
    result = analyze_code_patterns(code)
    detected = result["combined_score"] > 0.3
    return detected, result


def is_detected_combined(file_path: str) -> tuple:
    """결합 판정: 패턴 OR 앙상블"""
    p_detected, p_result = is_detected_by_pattern(file_path)
    e_detected, e_result = is_detected_by_ensemble(file_path)
    return (p_detected or e_detected), {
        "pattern_detected": p_detected,
        "ensemble_detected": e_detected,
        "ensemble_score": e_result["combined_score"],
    }


# ─── 타이포스쿼팅 테스트 케이스 ──────────────────────────────

TYPOSQUATTING_CASES = [
    # (패키지명, 악성여부, 예상 공식 패키지)
    # True Positive: 타이포스쿼팅으로 탐지해야 함
    ("reqeusts", True, "requests"),
    ("requets", True, "requests"),
    ("reqests", True, "requests"),
    ("numppy", True, "numpy"),
    ("nunpy", True, "numpy"),
    ("pandsa", True, "pandas"),
    ("pandass", True, "pandas"),
    ("flaask", True, "flask"),
    ("flassk", True, "flask"),
    ("djanogo", True, "django"),
    ("djnago", True, "django"),
    ("matplotib", True, "matplotlib"),
    ("pilllow", True, "pillow"),
    ("expresss", True, "express"),
    ("lodassh", True, "lodash"),
    # True Negative: 정상 패키지 (탐지하면 안 됨)
    ("requests", False, None),
    ("numpy", False, None),
    ("pandas", False, None),
    ("flask", False, None),
    ("django", False, None),
    ("scipy", False, None),
    ("matplotlib", False, None),
    ("pillow", False, None),
    ("fastapi", False, None),
    ("celery", False, None),
    ("redis", False, None),
    ("sqlalchemy", False, None),
    ("pydantic", False, None),
    ("boto3", False, None),
    ("pytest", False, None),
]


# ─── 벤치마크 실행 ───────────────────────────────────────────

def run_malware_benchmark(detection_func, method_name: str) -> BenchmarkResult:
    result = BenchmarkResult()

    for filepath in sorted(MALICIOUS_DIR.glob("*.py")):
        start = time.time()
        detected, detail = detection_func(str(filepath))
        elapsed = time.time() - start

        if detected:
            result.tp += 1
            status = "TP"
        else:
            result.fn += 1
            status = "FN (놓침)"

        result.details.append({
            "file": filepath.name, "label": "malicious",
            "detected": detected, "status": status,
            "time_ms": round(elapsed * 1000, 1),
        })

    for filepath in sorted(BENIGN_DIR.glob("*.py")):
        start = time.time()
        detected, detail = detection_func(str(filepath))
        elapsed = time.time() - start

        if detected:
            result.fp += 1
            status = "FP (오탐)"
        else:
            result.tn += 1
            status = "TN"

        result.details.append({
            "file": filepath.name, "label": "benign",
            "detected": detected, "status": status,
            "time_ms": round(elapsed * 1000, 1),
        })

    return result


def run_typosquatting_benchmark() -> BenchmarkResult:
    result = BenchmarkResult()
    for pkg_name, is_malicious, _ in TYPOSQUATTING_CASES:
        detected, official = detect_typosquatting(pkg_name)

        if is_malicious and detected:
            result.tp += 1
            status = "TP"
        elif is_malicious and not detected:
            result.fn += 1
            status = "FN (놓침)"
        elif not is_malicious and detected:
            result.fp += 1
            status = "FP (오탐)"
        else:
            result.tn += 1
            status = "TN"

        result.details.append({
            "package": pkg_name, "expected_malicious": is_malicious,
            "detected": detected, "matched_official": official, "status": status,
        })
    return result


# ─── 출력 ────────────────────────────────────────────────────

def print_header(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def print_metrics(result: BenchmarkResult):
    print(f"  Confusion Matrix:")
    print(f"    TP (정탐): {result.tp}  |  FP (오탐): {result.fp}")
    print(f"    FN (미탐): {result.fn}  |  TN (정상): {result.tn}")
    print()
    print(f"  Precision (정밀도):     {result.precision:.1%}")
    print(f"  Recall (재현율):        {result.recall:.1%}")
    print(f"  F1 Score:               {result.f1:.1%}")
    print(f"  Accuracy (정확도):      {result.accuracy:.1%}")
    print(f"  False Positive Rate:    {result.fp_rate:.1%}")


def print_details(result: BenchmarkResult):
    errors = [d for d in result.details if d["status"] not in ("TP", "TN")]
    if errors:
        print(f"\n  오분류 상세:")
        for d in errors:
            label = d.get("file") or d.get("package")
            print(f"    [{d['status']}] {label}")
    else:
        print(f"\n  모든 샘플 정확히 분류됨!")


def main():
    print("\n" + "=" * 60)
    print("  OSSGuard 보안 탐지 벤치마크")
    print(f"  샘플: 악성 {len(list(MALICIOUS_DIR.glob('*.py')))}개"
          f" / 정상 {len(list(BENIGN_DIR.glob('*.py')))}개"
          f" / 타이포스쿼팅 {len(TYPOSQUATTING_CASES)}개")
    print("=" * 60)

    total_start = time.time()
    all_results = {}

    # 1. 패턴 매칭 단독
    print_header("1. 패턴 매칭 단독 (malware.py)")
    r1 = run_malware_benchmark(is_detected_by_pattern, "pattern")
    print_metrics(r1)
    print_details(r1)
    all_results["pattern_matching"] = r1

    # 2. 앙상블 (패턴 + 엔트로피)
    print_header("2. 앙상블 분석 (code_analyzer.py)")
    r2 = run_malware_benchmark(is_detected_by_ensemble, "ensemble")
    print_metrics(r2)
    print_details(r2)
    all_results["ensemble"] = r2

    # 3. 결합 판정
    print_header("3. 결합 판정 (패턴 OR 앙상블)")
    r3 = run_malware_benchmark(is_detected_combined, "combined")
    print_metrics(r3)
    print_details(r3)
    all_results["combined"] = r3

    # 4. 타이포스쿼팅
    print_header("4. 타이포스쿼팅 탐지")
    r4 = run_typosquatting_benchmark()
    print_metrics(r4)
    print_details(r4)
    all_results["typosquatting"] = r4

    # 비교 요약
    total_elapsed = time.time() - total_start
    print_header("비교 요약")
    print(f"  {'방법':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FP Rate':>10}")
    print(f"  {'-' * 60}")
    for name, r in all_results.items():
        print(f"  {name:<20} {r.precision:>9.1%} {r.recall:>9.1%} {r.f1:>9.1%} {r.fp_rate:>9.1%}")
    print(f"\n  총 소요 시간: {total_elapsed:.2f}초")

    # JSON 리포트 저장
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "samples": {
            "malicious": len(list(MALICIOUS_DIR.glob("*.py"))),
            "benign": len(list(BENIGN_DIR.glob("*.py"))),
            "typosquatting": len(TYPOSQUATTING_CASES),
        },
        "results": {},
    }
    for name, r in all_results.items():
        report["results"][name] = {
            "tp": r.tp, "fp": r.fp, "tn": r.tn, "fn": r.fn,
            "precision": round(r.precision, 4),
            "recall": round(r.recall, 4),
            "f1": round(r.f1, 4),
            "fp_rate": round(r.fp_rate, 4),
            "accuracy": round(r.accuracy, 4),
            "details": r.details,
        }

    report_path = Path(__file__).resolve().parent / "benchmark_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  상세 리포트 저장: {report_path}")


if __name__ == "__main__":
    main()
