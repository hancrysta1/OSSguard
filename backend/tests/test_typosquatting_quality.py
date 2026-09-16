"""타이포스쿼팅 탐지 품질 회귀 테스트.

벤치마크 스크립트(`tests/benchmark/run_typo_benchmark.py`)는 탐지 로직을 사본으로 들고 있어
서비스 코드만 바뀌면 값이 어긋난다. 이 테스트는 운영에서 쓰는 `detect_typosquatting()`을
그대로 호출해 같은 표본으로 재현율·정밀도를 다시 계산하고, 기준 아래로 떨어지면 실패한다.

표본: 가짜 이름 12개(실제 사고 사례 2개 포함) + 정상 이름 15개 = 27개
"""

import pytest

from app.services.typosquatting import detect_typosquatting

# ─── 기준값 ───────────────────────────────────────────────
# 현재 값은 재현율 100%(12개 전부), 정밀도 100%.
# 표본 안에서는 한 건도 놓치지 않는 상태이므로 재현율을 100%로 고정하고,
# 정밀도는 정상 패키지를 하나라도 잡으면 실패하도록 100%로 고정한다.
MIN_RECALL = 1.00
MIN_PRECISION = 1.00

# 의도적으로 잡지 않기로 한 이름이 있으면 여기에 적는다. 지금은 없다.
# 여기 없는 이름이 미탐되면 테스트가 실패한다.
KNOWN_MISSES: set[str] = set()

# ─── 표본 ────────────────────────────────────────────────
TYPO_PACKAGES = [
    # 실제 사고 사례
    ("browser-cookies3", "2024.10 Socket 발견, browser-cookie3 위장, 196회 다운로드"),
    ("coloraiz", "2025.05 Checkmarx 발견, colorama 이름 혼동 캠페인"),
    # 글자 1개 추가
    ("requestss", "s 하나 추가"),
    ("flaskk", "k 하나 추가"),
    ("numpyy", "y 하나 추가"),
    ("pandass", "s 하나 추가"),
    ("expresss", "s 하나 추가"),
    # 글자 순서 변경
    ("djnago", "a 빠짐/순서 변경"),
    ("reqeusts", "e-u 위치 변경"),
    ("flaask", "a 추가"),
    # 글자 1개 변경
    ("requosts", "e→o 변경"),
    ("nunpy", "u 탈락"),
]

LEGIT_PACKAGES = [
    "requests", "numpy", "flask", "django", "browser-cookie3",
    "fastapi", "celery", "redis", "pytest", "boto3",
    "sqlalchemy", "pydantic", "uvicorn", "torch", "axios",
    # colorizr 은 npm 의 정상 색상 라이브러리다. 2025 Checkmarx 캠페인이 이 이름을 미끼로
    # 썼을 뿐 패키지 자체는 악성이 아니므로, 잡지 않는 것이 맞는 동작이다.
    "colorizr",
]

# 실제 공격에 쓰인 이름은 개별로도 반드시 잡혀야 한다.
REAL_INCIDENT_PACKAGES = ["browser-cookies3", "coloraiz"]

# 같은 캠페인에서 쓰인 접미사형 악성 패키지. 오타가 아니라 브랜드명 뒤에 말을 붙이는 유형이라
# 편집 거리·글자 삽입·교환 검사로는 잡히지 않는다. 지금은 못 잡는 영역이라 기준에 넣지 않고,
# 몇 개나 잡히는지만 로그로 남겨 개선 여부를 추적한다.
AFFIX_CAMPAIGN_PACKAGES = [
    "colorizator", "coloramapkgs", "coloramapkgsw",
    "coloramapkgsdow", "coloramashowtemp", "readmecolorama",
]


def _evaluate() -> dict:
    """표본 전체를 돌려 혼동행렬과 지표를 계산한다."""
    detected_typos = {name for name, _ in TYPO_PACKAGES if detect_typosquatting(name)[0]}
    missed_typos = {name for name, _ in TYPO_PACKAGES} - detected_typos
    false_positives = {name for name in LEGIT_PACKAGES if detect_typosquatting(name)[0]}

    tp, fn, fp = len(detected_typos), len(missed_typos), len(false_positives)
    tn = len(LEGIT_PACKAGES) - fp

    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": recall, "precision": precision, "f1": f1,
        "missed": missed_typos, "false_positives": false_positives,
    }


@pytest.fixture(scope="module")
def metrics() -> dict:
    return _evaluate()


def test_report_metrics(metrics):
    """지표를 로그로 남긴다(`pytest -s`). 실패시키지 않는 보고용."""
    print(
        f"\n표본 {len(TYPO_PACKAGES) + len(LEGIT_PACKAGES)}개"
        f"(가짜 {len(TYPO_PACKAGES)} / 정상 {len(LEGIT_PACKAGES)})"
        f"\n  TP {metrics['tp']}  FN {metrics['fn']}  FP {metrics['fp']}  TN {metrics['tn']}"
        f"\n  재현율 {metrics['recall']:.1%}  정밀도 {metrics['precision']:.1%}  F1 {metrics['f1']:.1%}"
        f"\n  미탐: {sorted(metrics['missed']) or '없음'}"
        f"\n  오탐: {sorted(metrics['false_positives']) or '없음'}"
    )


def test_recall_not_below_baseline(metrics):
    assert metrics["recall"] >= MIN_RECALL, (
        f"재현율이 기준 아래로 떨어졌습니다: {metrics['recall']:.1%} < {MIN_RECALL:.0%} "
        f"(미탐: {sorted(metrics['missed'])})"
    )


def test_no_false_positive_on_legit_packages(metrics):
    assert metrics["precision"] >= MIN_PRECISION, (
        f"정상 패키지를 잘못 잡았습니다: {sorted(metrics['false_positives'])}"
    )


def test_misses_do_not_grow(metrics):
    unexpected = metrics["missed"] - KNOWN_MISSES
    assert not unexpected, (
        f"알려진 미탐 외에 새로 놓친 패키지가 있습니다: {sorted(unexpected)}"
    )


def test_report_known_gap():
    """접미사형 캠페인 패키지를 몇 개나 잡는지 기록한다. 실패시키지 않는 보고용."""
    detected = [name for name in AFFIX_CAMPAIGN_PACKAGES if detect_typosquatting(name)[0]]
    print(
        f"\n접미사형 캠페인 표본 {len(AFFIX_CAMPAIGN_PACKAGES)}개 중 "
        f"{len(detected)}개 탐지 (현재 규칙이 다루지 못하는 영역)"
        f"\n  탐지: {detected or '없음'}"
    )


@pytest.mark.parametrize("package_name", REAL_INCIDENT_PACKAGES)
def test_real_incident_packages_detected(package_name):
    is_typo, official = detect_typosquatting(package_name)
    assert is_typo, f"실제 사고 패키지 '{package_name}'를 탐지하지 못했습니다"
    assert official, f"'{package_name}'의 정식 패키지명을 돌려주지 않았습니다"
