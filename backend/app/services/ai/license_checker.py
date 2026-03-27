"""AI-powered license compatibility analysis for SBOM packages."""

import json
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)

# License compatibility matrix (simplified)
# "permissive" can combine with anything
# "copyleft" requires derivative works to use same license
# "proprietary" conflicts with copyleft
LICENSE_CATEGORIES = {
    "MIT": "permissive",
    "Apache-2.0": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "ISC": "permissive",
    "Unlicense": "permissive",
    "CC0-1.0": "permissive",
    "0BSD": "permissive",
    "GPL-2.0-only": "strong_copyleft",
    "GPL-2.0-or-later": "strong_copyleft",
    "GPL-3.0-only": "strong_copyleft",
    "GPL-3.0-or-later": "strong_copyleft",
    "AGPL-3.0-only": "strong_copyleft",
    "AGPL-3.0-or-later": "strong_copyleft",
    "LGPL-2.1-only": "weak_copyleft",
    "LGPL-2.1-or-later": "weak_copyleft",
    "LGPL-3.0-only": "weak_copyleft",
    "LGPL-3.0-or-later": "weak_copyleft",
    "MPL-2.0": "weak_copyleft",
    "EPL-2.0": "weak_copyleft",
}

# Known conflicts: (category_a, category_b) -> conflict description
CONFLICT_RULES = [
    (
        "strong_copyleft", "strong_copyleft",
        lambda a, b: a != b,  # GPL-2.0 + GPL-3.0 = conflict
        "GPL 버전이 서로 다른 라이선스는 호환되지 않을 수 있습니다",
    ),
]


def analyze_license_compatibility(analysis_data: dict) -> dict:
    """Analyze license compatibility across all SBOM packages.

    Returns:
    - overall_status: "compatible", "warning", "conflict"
    - licenses_found: dict of license -> count
    - conflicts: list of detected conflicts
    - recommendations: list of actions
    """
    packages = analysis_data.get("packages", [])

    # Extract licenses
    license_map = {}  # license_name -> [package_names]
    unknown_licenses = []

    for pkg in packages:
        name = pkg.get("name", pkg.get("package_name", "unknown"))
        license_id = pkg.get("licenseConcluded", pkg.get("license", "NOASSERTION"))

        if not license_id or license_id in ("NOASSERTION", "Unknown", "NONE", ""):
            unknown_licenses.append(name)
            continue

        # Normalize
        normalized = _normalize_license(license_id)
        if normalized not in license_map:
            license_map[normalized] = []
        license_map[normalized].append(name)

    # Detect conflicts
    conflicts = _detect_conflicts(license_map)

    # Categorize
    categories_found = set()
    for lic in license_map:
        cat = LICENSE_CATEGORIES.get(lic, "unknown")
        categories_found.add(cat)

    # Determine overall status
    if conflicts:
        status = "conflict"
    elif "strong_copyleft" in categories_found:
        status = "warning"
    elif unknown_licenses:
        status = "warning"
    else:
        status = "compatible"

    # Build recommendations
    recommendations = _build_recommendations(license_map, unknown_licenses, conflicts, categories_found)

    return {
        "status": status,
        "total_packages": len(packages),
        "licenses_found": {lic: len(pkgs) for lic, pkgs in license_map.items()},
        "unknown_license_packages": unknown_licenses[:20],
        "unknown_count": len(unknown_licenses),
        "categories": sorted(categories_found),
        "conflicts": conflicts,
        "recommendations": recommendations,
    }


async def analyze_license_with_ai(analysis_data: dict) -> dict:
    """Enhanced license analysis with AI explanations."""
    base_result = analyze_license_compatibility(analysis_data)

    try:
        import ollama

        prompt = f"""당신은 오픈소스 라이선스 전문가입니다.

다음 오픈소스 프로젝트의 라이선스 분석 결과를 검토하고, 한국어로 실무적인 조언을 해주세요.

발견된 라이선스: {json.dumps(base_result['licenses_found'], ensure_ascii=False)}
카테고리: {base_result['categories']}
충돌: {json.dumps(base_result['conflicts'], ensure_ascii=False) if base_result['conflicts'] else '없음'}
라이선스 미상 패키지: {base_result['unknown_count']}개

다음을 포함해주세요:
1. 전체 라이선스 호환성 평가 (2문장)
2. 주의해야 할 점 (있다면)
3. 상업적 사용 시 고려사항

간결하게 답변해주세요."""

        response = ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.3, "num_predict": 512},
        )
        base_result["ai_analysis"] = response["message"]["content"]

    except Exception as e:
        log.warning("license_ai_failed", error=str(e))
        base_result["ai_analysis"] = _template_license_summary(base_result)

    return base_result


def _normalize_license(license_id: str) -> str:
    """Normalize license identifier."""
    # Strip common prefixes/suffixes
    normalized = license_id.strip()

    # Handle SPDX expressions
    if " AND " in normalized or " OR " in normalized:
        # Take the most restrictive
        parts = normalized.replace(" AND ", "|").replace(" OR ", "|").split("|")
        return parts[0].strip()

    # Common aliases
    aliases = {
        "MIT License": "MIT",
        "Apache License 2.0": "Apache-2.0",
        "BSD License": "BSD-3-Clause",
        "GNU General Public License v3": "GPL-3.0-only",
        "GNU General Public License v2": "GPL-2.0-only",
        "LGPL": "LGPL-2.1-or-later",
        "MPL": "MPL-2.0",
    }
    return aliases.get(normalized, normalized)


def _detect_conflicts(license_map: dict) -> list[dict]:
    """Detect license compatibility conflicts."""
    conflicts = []
    licenses = list(license_map.keys())

    for i in range(len(licenses)):
        for j in range(i + 1, len(licenses)):
            lic_a, lic_b = licenses[i], licenses[j]
            cat_a = LICENSE_CATEGORIES.get(lic_a, "unknown")
            cat_b = LICENSE_CATEGORIES.get(lic_b, "unknown")

            # GPL + AGPL conflict
            if ("GPL" in lic_a and "AGPL" in lic_b) or ("AGPL" in lic_a and "GPL" in lic_b):
                conflicts.append({
                    "license_a": lic_a,
                    "license_b": lic_b,
                    "packages_a": license_map[lic_a][:5],
                    "packages_b": license_map[lic_b][:5],
                    "severity": "HIGH",
                    "description": f"{lic_a}와 {lic_b}는 호환되지 않을 수 있습니다",
                })

            # GPL-2.0 + GPL-3.0 (one-way compatibility only)
            if "GPL-2.0" in lic_a and "GPL-3.0" in lic_b:
                conflicts.append({
                    "license_a": lic_a,
                    "license_b": lic_b,
                    "packages_a": license_map[lic_a][:5],
                    "packages_b": license_map[lic_b][:5],
                    "severity": "MEDIUM",
                    "description": "GPL-2.0-only와 GPL-3.0은 단방향 호환만 가능합니다",
                })

    return conflicts


def _build_recommendations(license_map, unknown_licenses, conflicts, categories):
    """Generate actionable recommendations."""
    recs = []

    if conflicts:
        recs.append("라이선스 충돌이 발견되었습니다. 법무팀 검토가 필요합니다.")

    if "strong_copyleft" in categories:
        copyleft_licenses = [
            lic for lic in license_map if LICENSE_CATEGORIES.get(lic) == "strong_copyleft"
        ]
        recs.append(
            f"GPL 계열 라이선스({', '.join(copyleft_licenses)}) 사용 중입니다. "
            "소스 코드 공개 의무가 발생할 수 있습니다."
        )

    if len(unknown_licenses) > 0:
        recs.append(
            f"{len(unknown_licenses)}개 패키지의 라이선스가 확인되지 않았습니다. "
            "수동 확인이 필요합니다."
        )

    if not recs:
        recs.append("모든 패키지의 라이선스가 호환됩니다.")

    return recs


def _template_license_summary(result: dict) -> str:
    """Fallback template summary when AI is unavailable."""
    status = result["status"]
    if status == "conflict":
        return "라이선스 충돌이 감지되었습니다. 상세 내용을 확인하고 법무팀과 검토하세요."
    elif status == "warning":
        return "일부 라이선스에 주의가 필요합니다. Copyleft 라이선스 사용 시 소스 공개 의무를 확인하세요."
    return "모든 라이선스가 호환됩니다. 상업적 사용에도 문제가 없습니다."
