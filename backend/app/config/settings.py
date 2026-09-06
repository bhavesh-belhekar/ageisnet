from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the AegisNet backend."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "AegisNet Backend"
    debug: bool = False

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "aegisnet"
    postgres_password: str = "aegisnet"
    postgres_db: str = "aegisnet"

    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str | None = None

    neo4j_host: str = "localhost"
    neo4j_port: int = 7687
    neo4j_user: str = "neo4j"
    neo4j_password: str = "aegisnet"


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
