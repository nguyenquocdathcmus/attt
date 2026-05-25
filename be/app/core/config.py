from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_env: str = "local"
    database_url: str = "postgresql+psycopg2://user:pass@localhost:5432/secdb"
    redis_url: str = "redis://localhost:6379/0"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    embeddings_model: str = "nomic-embed-text"
    zap_base_url: str = "http://localhost:8080"
    zap_api_key: str = ""
    jwt_secret: str = "change-me"
    access_token_expire_minutes: int = 60
    auth_enabled: bool = True
    log_level: str = "INFO"


settings = Settings()
