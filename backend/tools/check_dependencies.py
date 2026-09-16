#!/usr/bin/env python3
"""의존성 파일을 읽어 타이포스쿼팅 의심 패키지가 있는지 검사한다.

서비스의 설치 전 사전 검사(`POST /pypi-npm/pre-check`)와 같은 함수
`app.services.typosquatting.detect_typosquatting()`을 그대로 호출한다.
CI에서 돌려, 위험한 패키지가 의존성에 추가된 변경은 머지되기 전에 막는 용도다.

사용법:
    python tools/check_dependencies.py ../backend/pyproject.toml ../frontend/package.json
    python tools/check_dependencies.py --allow my-pkg --allow other-pkg requirements.txt

종료 코드:
    0  의심 패키지 없음
    1  의심 패키지 발견 (머지 차단)
    2  파일을 읽지 못함
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.typosquatting import detect_typosquatting  # noqa: E402

# `requests==2.26.0`, `celery[redis]>=5.4.0`, `httpx ; python_version>'3.9'` 등에서 이름만 남긴다.
_REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9._-]+")


def parse_requirements(path: str) -> list[str]:
    names = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            match = _REQUIREMENT_NAME.match(line)
            if match:
                names.append(match.group(0))
    return names


def parse_pyproject(path: str) -> list[str]:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for extra_deps in project.get("optional-dependencies", {}).values():
        specs.extend(extra_deps)

    names = []
    for spec in specs:
        match = _REQUIREMENT_NAME.match(spec.strip())
        if match:
            names.append(match.group(0))
    return names


def parse_package_json(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    names = list(data.get("dependencies", {}))
    names.extend(data.get("devDependencies", {}))
    return names


def collect_packages(path: str) -> list[str]:
    basename = os.path.basename(path)
    if basename == "package.json":
        return parse_package_json(path)
    if basename == "pyproject.toml":
        return parse_pyproject(path)
    if basename.startswith("requirements") and basename.endswith(".txt"):
        return parse_requirements(path)
    raise ValueError(f"지원하지 않는 의존성 파일: {basename}")


def main() -> int:
    parser = argparse.ArgumentParser(description="의존성 타이포스쿼팅 검사")
    parser.add_argument("files", nargs="+", help="requirements.txt / pyproject.toml / package.json")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="NAME",
        help="의심으로 잡혔지만 정상임이 확인된 패키지 (반복 지정 가능)",
    )
    args = parser.parse_args()

    allowed = {name.lower() for name in args.allow}
    findings: list[tuple[str, str, str]] = []
    total = 0

    for path in args.files:
        try:
            packages = collect_packages(path)
        except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as e:
            print(f"[오류] {path}: {e}", file=sys.stderr)
            return 2

        total += len(packages)
        print(f"{path} — 패키지 {len(packages)}개 검사")

        for name in packages:
            if name.lower() in allowed:
                continue
            is_typo, official = detect_typosquatting(name)
            if is_typo:
                findings.append((path, name, official))

    print()
    if not findings:
        print(f"의심 패키지 없음 (총 {total}개 검사)")
        return 0

    print(f"타이포스쿼팅 의심 패키지 {len(findings)}건 — 의존성을 확인하세요")
    for path, name, official in findings:
        print(f"  {path}: '{name}' → 정식 패키지 '{official}'와(과) 이름이 비슷합니다")
    print()
    print("정상 패키지라면 --allow 로 제외하고, 그 근거를 PR 설명에 남기세요.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
