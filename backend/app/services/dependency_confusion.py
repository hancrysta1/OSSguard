import os
from app.utils.logging import get_logger

log = get_logger(__name__)

TRUSTED_SOURCES = {"Official", "TrustedOrg", "PyPI", "InternalRepo"}
INTERNAL_KEYWORDS = {"private", "internal", "corp", "enterprise", "inhouse"}


def check_dependency_confusion(internal_deps_file: str) -> list[dict]:
    results = []
    if not os.path.exists(internal_deps_file):
        return [{"message": "No internal_deps.txt file found"}]

    try:
        with open(internal_deps_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        log.error("dependency_confusion_read_failed", error=str(e))
        return [{"error": f"Failed to read internal_deps.txt: {str(e)}"}]

    for idx, line in enumerate(lines, start=1):
        line_strip = line.strip()
        if not line_strip or line_strip.startswith("#"):
            continue
        parts = [p.strip() for p in line_strip.split(",")]
        if len(parts) >= 2:
            name = parts[0].lower()
            distributor = parts[1]
            if any(kw in name for kw in INTERNAL_KEYWORDS):
                if distributor not in TRUSTED_SOURCES:
                    results.append({
                        "line": idx,
                        "dependency": name,
                        "distributor": distributor,
                        "risk": "Dependency confusion risk detected",
                    })

    if not results:
        results.append({"message": "No dependency confusion detected"})
    return results
