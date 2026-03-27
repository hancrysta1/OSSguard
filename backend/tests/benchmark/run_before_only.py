#!/usr/bin/env python3
"""Before 버전만 실행 (캡처용) - 기존 방식의 한계를 보여줌"""
import difflib

# 기존 방식: 10개 패키지, SequenceMatcher, threshold 0.9
OFFICIAL_PACKAGES = {"requests","numpy","pandas","express","lodash","flask","django","scipy","matplotlib","pillow"}
THRESHOLD = 0.9

def detect_before(pkg):
    name = pkg.lower()
    if name in OFFICIAL_PACKAGES:
        return False, None
    for off in OFFICIAL_PACKAGES:
        sim = difflib.SequenceMatcher(None, name, off).ratio()
        if sim >= THRESHOLD:
            return True, off
    return False, None

# 테스트 케이스
CASES = [
    ("browser-cookies3", True, "실제 악성 패키지 (196회 다운로드)"),
    ("requestss",        True, "s 하나 추가"),
    ("djnago",           True, "글자 순서 변경"),
    ("reqeusts",         True, "글자 위치 변경"),
    ("nunpy",            True, "글자 탈락"),
    ("requests",         False, "정상 패키지"),
    ("numpy",            False, "정상 패키지"),
    ("flask",            False, "정상 패키지"),
    ("fastapi",          False, "정상 패키지"),
]

print("=" * 55)
print("  Before: 기존 타이포스쿼팅 탐지")
print("  패키지 목록: 10개 | 알고리즘: SequenceMatcher")
print("  Threshold: 0.9")
print("=" * 55)
print()

tp=fp=tn=fn=0
for pkg, expected, desc in CASES:
    detected, official = detect_before(pkg)
    if expected and detected:     tp+=1; print(f"  [TP 탐지] {pkg:<25} → {official}")
    elif expected and not detected: fn+=1; print(f"  [FN 놓침] {pkg:<25}   ({desc})")
    elif not expected and detected: fp+=1; print(f"  [FP 오탐] {pkg:<25} → {official}")
    else:                           tn+=1; print(f"  [TN 정상] {pkg:<25}   ({desc})")

print()
prec = tp/(tp+fp) if tp+fp else 0
rec = tp/(tp+fn) if tp+fn else 0
f1 = 2*prec*rec/(prec+rec) if prec+rec else 0
print(f"  Precision: {prec:.1%}  Recall: {rec:.1%}  F1: {f1:.1%}")
print()
print(f"  ※ browser-cookies3: 목록에 browser-cookie3가 없어서 비교 자체를 안 함")
print(f"  ※ djnago, reqeusts: SequenceMatcher가 글자 순서 변경에 약함")
