#!/usr/bin/env python3
"""타이포스쿼팅 탐지 Before/After 벤치마크"""
import difflib

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


# ═══════════ After: 개선 방식 (100+개, 다중 알고리즘) ═══════════

AFTER_PACKAGES = {
    "requests","numpy","pandas","flask","django","scipy","matplotlib",
    "pillow","setuptools","pip","wheel","boto3","botocore","urllib3",
    "certifi","idna","charset-normalizer","typing-extensions","pyyaml",
    "cryptography","pydantic","jinja2","markupsafe","click","packaging",
    "colorama","attrs","pluggy","pytz","pytest","virtualenv","tomli",
    "filelock","platformdirs","coverage","pygments",
    "sqlalchemy","aiohttp","grpcio","protobuf","wrapt","decorator",
    "cffi","pycparser","greenlet","httpx","httpcore","anyio","sniffio",
    "rich","fastapi","uvicorn","starlette","celery","redis","psycopg2",
    "beautifulsoup4","lxml","selenium","scrapy","paramiko",
    "python-dateutil","tqdm","tabulate","black",
    "isort","flake8","mypy","pylint","bandit","safety",
    "transformers","torch","tensorflow","keras","scikit-learn",
    "opencv-python","imageio",
    "browser-cookie3","pycookiecheat",
    "express","lodash","react","vue","angular","axios","moment",
    "webpack","babel","eslint","prettier","typescript","chalk","debug",
    "commander","inquirer","yargs","glob","minimist","dotenv",
    "jsonwebtoken","bcrypt","cors","helmet","morgan","nodemon",
    "mongoose","sequelize","knex","socket.io","ws","uuid",
    "next","nuxt","gatsby","svelte","tailwindcss","postcss",
    "jest","mocha","chai","sinon","cypress","puppeteer",
}
AFTER_THRESHOLD = 0.85

def _levenshtein(s1, s2):
    if len(s1) < len(s2): return _levenshtein(s2, s1)
    if not s2: return len(s1)
    prev = range(len(s2)+1)
    for i, c1 in enumerate(s1):
        curr = [i+1]
        for j, c2 in enumerate(s2):
            curr.append(min(curr[j]+1, prev[j+1]+1, prev[j]+(0 if c1==c2 else 1)))
        prev = curr
    return prev[-1]

def _has_swap(s1, s2):
    if len(s1)!=len(s2): return False
    diffs=[(i,a,b) for i,(a,b) in enumerate(zip(s1,s2)) if a!=b]
    return len(diffs)==2 and diffs[0][1]==diffs[1][2] and diffs[0][2]==diffs[1][1]

def _has_insert(s1, s2):
    if abs(len(s1)-len(s2))!=1: return False
    short,long=(s1,s2) if len(s1)<len(s2) else (s2,s1)
    skip=False; j=0
    for i in range(len(long)):
        if j<len(short) and long[i]==short[j]: j+=1
        elif not skip: skip=True
        else: return False
    return True

def detect_after(pkg):
    name = pkg.lower().strip()
    if name in {p.lower() for p in AFTER_PACKAGES}: return False, None
    for off in AFTER_PACKAGES:
        o = off.lower()
        if _has_insert(name, o): return True, off
        if _has_swap(name, o): return True, off
        if _levenshtein(name, o) <= 2 and len(name) >= 4: return True, off
        if difflib.SequenceMatcher(None, name, o).ratio() >= AFTER_THRESHOLD: return True, off
    return False, None


# ═══════════ 테스트 케이스 ═══════════

CASES = [
    # ─── 실제 사건 기반 ───
    ("browser-cookies3",  True,  "browser-cookie3",  "2026 Socket.dev 발견, 196회 다운로드"),
    ("colorizr",          True,  "colorama",         "2024 Checkmarx 발견, colorama 타이포"),

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
a = run_benchmark("After (100+개 패키지, 다중 알고리즘)", detect_after)

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
