"""Benign: Legitimate use of base64 for image encoding in API."""
import base64
from pathlib import Path


def image_to_base64(image_path: str) -> str:
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def base64_to_image(encoded: str, output_path: str) -> None:
    data = base64.b64decode(encoded)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(data)


def create_data_uri(image_path: str, mime_type: str = "image/png") -> str:
    encoded = image_to_base64(image_path)
    return f"data:{mime_type};base64,{encoded}"
