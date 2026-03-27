"""Benign: Test helper with assertions."""
import json
import tempfile
from pathlib import Path


def create_temp_file(content: str, suffix: str = ".txt") -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


def assert_json_valid(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, (dict, list))
    return data


def compare_outputs(expected: dict, actual: dict) -> list[str]:
    diffs = []
    for key in expected:
        if key not in actual:
            diffs.append(f"Missing key: {key}")
        elif expected[key] != actual[key]:
            diffs.append(f"Mismatch on {key}: {expected[key]} != {actual[key]}")
    return diffs
