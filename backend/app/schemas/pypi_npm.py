from pydantic import BaseModel
from typing import Optional


class PackageRequest(BaseModel):
    package_manager: str
    package_name: str
    package_version: Optional[str] = None
