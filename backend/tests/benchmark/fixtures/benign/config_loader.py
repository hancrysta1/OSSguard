"""Benign: Configuration loader with environment variables."""
import os
from dataclasses import dataclass


@dataclass
class Config:
    database_url: str
    debug: bool
    log_level: str
    max_workers: int


def load_config() -> Config:
    return Config(
        database_url=os.environ.get("DATABASE_URL", "sqlite:///local.db"),
        debug=os.environ.get("DEBUG", "false").lower() == "true",
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        max_workers=int(os.environ.get("MAX_WORKERS", "4")),
    )
