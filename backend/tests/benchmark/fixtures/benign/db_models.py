"""Benign: SQLAlchemy database models."""
from datetime import datetime


class User:
    def __init__(self, username: str, email: str):
        self.username = username
        self.email = email
        self.created_at = datetime.utcnow()
        self.is_active = True

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at.isoformat(),
            "is_active": self.is_active,
        }


class Package:
    def __init__(self, name: str, version: str, license_type: str):
        self.name = name
        self.version = version
        self.license_type = license_type

    def is_copyleft(self) -> bool:
        return self.license_type in ("GPL-2.0", "GPL-3.0", "AGPL-3.0")
