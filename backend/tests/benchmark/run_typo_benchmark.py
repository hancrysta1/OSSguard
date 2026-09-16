#!/usr/bin/env python3
"""타이포스쿼팅 탐지 Before/After 벤치마크

After는 서비스 코드(`app.services.typosquatting`)를 그대로 호출한다. 사본을 두면
서비스 코드가 바뀌어도 점수가 그대로라 값이 실제 동작을 보증하지 못하기 때문이다.
Before는 이미 없어진 옛 로직이라 재현용 사본을 남겨 둔다.

실행: backend 디렉터리에서 `python3 tests/benchmark/run_typo_benchmark.py`
(서비스 코드 임포트에 Python 3.11+ 와 structlog, pydantic-settings 가 필요하다.)
"""
import difflib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# ═══════════ Before: 기존 방식 (10개 패키지, threshold 0.9) ═══════════

BEFORE_PACKAGES = {"requests","numpy","pandas","express","lodash","flask","django","scipy","matplotlib","pillow"}
BEFORE_THRESHOLD = 0.9

def detect_before(pkg):
    name = pkg.lower()
    if name in BEFORE_PACKAGES:
        return False, None
    for off in BEFORE_PACKAGES:
        if difflib.SequenceMatcher(None, name, off).ratio() >= BEFORE_THRESHOLD:
            return True, off
    return False, None


# ═══════════ After: 현재 서비스 코드를 그대로 호출 ═══════════

from app.services.typosquatting import detect_typosquatting as detect_after  # noqa: E402


# ═══════════ 테스트 케이스 ═══════════

CASES = [
    # ─── 실제 사건 기반 ───
    ("browser-cookies3",  True,  "browser-cookie3",  "2024.10 Socket 발견, 196회 다운로드"),
    ("coloraiz",          True,  "colorama",         "2025.05 Checkmarx 발견, colorama 이름 혼동 캠페인"),

    # ─── 글자 1개 추가/삭제 (insertion) ───
    ("requestss",         True,  "requests",         "s 하나 추가"),
    ("flaskk",            True,  "flask",            "k 하나 추가"),
    ("numpyy",            True,  "numpy",            "y 하나 추가"),
    ("pandass",           True,  "pandas",           "s 하나 추가"),
    ("expresss",          True,  "express",          "s 하나 추가"),

    # ─── 글자 순서 변경 (transposition) ───
    ("djnago",            True,  "django",           "a 빠짐/순서변경"),
    ("reqeusts",          True,  "requests",         "e-u 위치 변경"),
    ("flaask",            True,  "flask",            "a 추가"),

    # ─── 글자 1개 변경 (substitution) ───
    ("requosts",          True,  "requests",         "e→o 변경"),
    ("nunpy",             True,  "numpy",            "u 탈락"),

    # ─── 정상 패키지 (탐지하면 안 됨) ───
    ("requests",          False, None,               "정상 패키지"),
    ("numpy",             False, None,               "정상 패키지"),
    ("flask",             False, None,               "정상 패키지"),
    ("django",            False, None,               "정상 패키지"),
    ("browser-cookie3",   False, None,               "정상 패키지"),
    ("fastapi",           False, None,               "정상 패키지"),
    ("celery",            False, None,               "정상 패키지"),
    ("redis",             False, None,               "정상 패키지"),
    ("pytest",            False, None,               "정상 패키지"),
    ("boto3",             False, None,               "정상 패키지"),
    ("sqlalchemy",        False, None,               "정상 패키지"),
    ("pydantic",          False, None,               "정상 패키지"),
    ("uvicorn",           False, None,               "정상 패키지"),
    ("torch",             False, None,               "정상 패키지"),
    ("axios",             False, None,               "정상 패키지"),
    ("colorizr",          False, None,               "npm 정상 패키지 — 위 캠페인이 이름만 도용"),
]


def run_benchmark(name, detect_func):
    tp=fp=tn=fn=0
    errors = []
    for pkg, expected_mal, expected_off, desc in CASES:
        detected, official = detect_func(pkg)
        if expected_mal and detected:     tp += 1
        elif expected_mal and not detected: fn += 1; errors.append(f"    [FN 놓침] {pkg} ({desc})")
        elif not expected_mal and detected: fp += 1; errors.append(f"    [FP 오탐] {pkg} → {official}")
        else: tn += 1

    prec = tp/(tp+fp) if tp+fp else 0
    rec = tp/(tp+fn) if tp+fn else 0
    f1 = 2*prec*rec/(prec+rec) if prec+rec else 0
    fpr = fp/(fp+tn) if fp+tn else 0

    print(f"\n  === {name} ===")
    print(f"  TP:{tp} FP:{fp} FN:{fn} TN:{tn}")
    print(f"  Precision: {prec:.1%}  Recall: {rec:.1%}  F1: {f1:.1%}  FP Rate: {fpr:.1%}")
    if errors:
        print(f"\n  오분류:")
        for e in errors: print(e)
    else:
        print(f"\n  모든 샘플 정확히 분류!")
    return {"tp":tp,"fp":fp,"fn":fn,"tn":tn,"prec":prec,"rec":rec,"f1":f1,"fpr":fpr}


mal_count = sum(1 for _,m,_,_ in CASES if m)
ben_count = sum(1 for _,m,_,_ in CASES if not m)
print(f"{'='*60}")
print(f"  타이포스쿼팅 탐지 벤치마크: Before vs After")
print(f"  샘플: 악성 {mal_count}개 / 정상 {ben_count}개")
print(f"{'='*60}")

b = run_benchmark("Before (10개 패키지, SequenceMatcher 0.9)", detect_before)
a = run_benchmark("After (서비스 코드 app.services.typosquatting 호출)", detect_after)

print(f"\n{'='*60}")
print(f"  Before vs After 비교")
print(f"{'='*60}")
print(f"  {'지표':<15} {'Before':>10} {'After':>10} {'변화':>10}")
print(f"  {'-'*45}")
for name, bv, av in [
    ("Precision", b["prec"], a["prec"]),
    ("Recall", b["rec"], a["rec"]),
    ("F1 Score", b["f1"], a["f1"]),
    ("FP Rate", b["fpr"], a["fpr"]),
]:
    diff = av - bv
    arrow = "↑" if diff > 0.001 else "↓" if diff < -0.001 else "→"
    if name == "FP Rate": arrow = "↓(개선)" if diff < -0.001 else "↑(악화)" if diff > 0.001 else "→"
    print(f"  {name:<15} {bv:>9.1%} {av:>9.1%} {arrow:>10}")
print()
