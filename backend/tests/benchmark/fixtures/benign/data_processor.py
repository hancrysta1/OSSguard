"""Benign: Data processing with pandas."""
import json
import csv
from pathlib import Path


def load_csv(filepath: str) -> list[dict]:
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def transform_data(records: list[dict]) -> list[dict]:
    return [
        {"name": r["name"].strip().lower(), "value": float(r["value"])}
        for r in records
        if r.get("value")
    ]


def save_json(data: list[dict], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
