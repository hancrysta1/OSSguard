import os
import difflib
from app.utils.logging import get_logger

log = get_logger(__name__)

# PyPI/npm 인기 패키지 상위 100+ (주기적으로 업데이트 필요)
OFFICIAL_PACKAGES = {
    # Python (PyPI 상위)
    "requests", "numpy", "pandas", "flask", "django", "scipy", "matplotlib",
    "pillow", "setuptools", "pip", "wheel", "boto3", "botocore", "urllib3",
    "certifi", "idna", "charset-normalizer", "typing-extensions", "pyyaml",
    "cryptography", "pydantic", "jinja2", "markupsafe", "click", "packaging",
    "colorama", "attrs", "pluggy", "pytz", "pytest", "virtualenv", "tomli",
    "filelock", "platformdirs", "exceptiongroup", "coverage", "pygments",
    "sqlalchemy", "aiohttp", "grpcio", "protobuf", "wrapt", "decorator",
    "cffi", "pycparser", "greenlet", "httpx", "httpcore", "anyio", "sniffio",
    "rich", "fastapi", "uvicorn", "starlette", "celery", "redis", "psycopg2",
    "beautifulsoup4", "lxml", "selenium", "scrapy", "paramiko", "fabric",
    "python-dateutil", "arrow", "pendulum", "tqdm", "tabulate", "black",
    "isort", "flake8", "mypy", "pylint", "bandit", "safety",
    "transformers", "torch", "tensorflow", "keras", "scikit-learn",
    "opencv-python", "Pillow", "imageio",
    "browser-cookie3", "pycookiecheat",
    # npm 상위
    "express", "lodash", "react", "vue", "angular", "axios", "moment",
    "webpack", "babel", "eslint", "prettier", "typescript", "chalk", "debug",
    "commander", "inquirer", "yargs", "glob", "minimist", "dotenv",
    "jsonwebtoken", "bcrypt", "cors", "helmet", "morgan", "nodemon",
    "mongoose", "sequelize", "knex", "socket.io", "ws", "uuid",
    "next", "nuxt", "gatsby", "svelte", "tailwindcss", "postcss",
    "jest", "mocha", "chai", "sinon", "cypress", "puppeteer",
}

THRESHOLD = 0.85  # 0.9 → 0.85로 낮춰 transposition 탐지 강화


def _levenshtein_distance(s1: str, s2: str) -> int:
    """편집 거리 계산 (글자 추가/삭제/변경 몇 번이면 같아지는지)"""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,       # 삽입
                prev_row[j + 1] + 1,   # 삭제
                prev_row[j] + cost,    # 변경
            ))
        prev_row = curr_row
    return prev_row[-1]


def _has_char_swap(s1: str, s2: str) -> bool:
    """글자 순서만 바뀐 건지 확인 (transposition 탐지)"""
    if len(s1) != len(s2):
        return False
    diffs = [(i, c1, c2) for i, (c1, c2) in enumerate(zip(s1, s2)) if c1 != c2]
    if len(diffs) == 2:
        i, a1, a2 = diffs[0]
        j, b1, b2 = diffs[1]
        return a1 == b2 and a2 == b1
    return False


def _has_char_insertion(s1: str, s2: str) -> bool:
    """글자 하나만 추가/삭제된 건지 확인 (browser-cookie3 → browser-cookies3)"""
    if abs(len(s1) - len(s2)) != 1:
        return False
    short, long = (s1, s2) if len(s1) < len(s2) else (s2, s1)
    skipped = False
    j = 0
    for i in range(len(long)):
        if j < len(short) and long[i] == short[j]:
            j += 1
        elif not skipped:
            skipped = True
        else:
            return False
    return True


def detect_typosquatting(package_name: str) -> tuple[bool, str | None]:
    name = package_name.lower().strip()

    if name in {p.lower() for p in OFFICIAL_PACKAGES}:
        return False, None

    for official in OFFICIAL_PACKAGES:
        off = official.lower()

        # 1. 글자 하나 추가/삭제 (browser-cookie3 → browser-cookies3)
        if _has_char_insertion(name, off):
            return True, official

        # 2. 글자 순서 변경 (django → djnago)
        if _has_char_swap(name, off):
            return True, official

        # 3. 편집 거리 1~2 이내
        dist = _levenshtein_distance(name, off)
        if dist <= 2 and len(name) >= 4:
            return True, official

        # 4. SequenceMatcher 유사도 (기존 방식, threshold 낮춤)
        similarity = difflib.SequenceMatcher(None, name, off).ratio()
        if similarity >= THRESHOLD:
            return True, official

    return False, None


def run_typosquatting_check(requirements_path: str) -> list[dict]:
    results = []
    if not os.path.exists(requirements_path):
        return [{"message": "No requirements.txt file found"}]

    with open(requirements_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for idx, line in enumerate(lines, start=1):
        pkg_line = line.strip()
        if pkg_line and not pkg_line.startswith("#"):
            pkg_name = pkg_line.split("==")[0].strip()
            is_typo, official = detect_typosquatting(pkg_name)
            if is_typo:
                similarity = difflib.SequenceMatcher(None, pkg_name.lower(), official.lower()).ratio()
                results.append({
                    "line": idx,
                    "pkg_line": pkg_line,
                    "typo_pkg": pkg_name,
                    "official_pkg": official,
                    "similarity": round(similarity, 2),
                })

    if not results:
        results.append({"message": "No typosquatting detected"})
    return results
