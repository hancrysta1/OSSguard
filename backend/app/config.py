from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    # Redis (cache + message broker + pub/sub 통합)
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    # Tool paths
    SYFT_PATH: str = "syft"
    TRIVY_PATH: str = "trivy"
    YARA_RULES_DIR: str = str(Path(__file__).resolve().parent.parent / "yara_rules")

    # AI - Ollama
    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"

    # AI - CodeBERT
    CODEBERT_MODEL: str = "microsoft/codebert-base"
    CODEBERT_CONFIDENCE_THRESHOLD: float = 0.7

    # Logging
    LOG_LEVEL: str = "INFO"

    @property
    def redis_url(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def celery_broker_url(self) -> str:
        return self.redis_url

    @property
    def celery_result_backend(self) -> str:
        return self.redis_url

    model_config = {"env_prefix": "OSSGUARD_"}


settings = Settings()
