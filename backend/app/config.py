"""Environment-driven settings for the standalone face-verification backend.

All settings use the ``FV_`` env prefix. This service is fully decoupled from
the digital-banking platform: its own database, its own keys, its own config.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# DEV-ONLY Fernet key so a bare checkout runs out of the box.
# Any real deployment MUST set FV_AT_REST_KEY (a fresh `Fernet.generate_key()`).
# Rotating/changing it makes previously stored embeddings unreadable.
_DEV_ONLY_AT_REST_KEY = "6Mn63B3HGwFzFOVl6czGyPlDbzMDyCt9PyvTIEy0dxE="


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FV_", env_file=".env", extra="ignore")

    # This service's OWN database file. Never the banking database.
    database_url: str = "sqlite+aiosqlite:///./face-verify.db"

    # Fernet key for at-rest encryption of stored embeddings.
    at_rest_key: str = _DEV_ONLY_AT_REST_KEY

    # PEM RSA private key used to unseal `enc1:` envelopes. The DEV pair below
    # is this app's OWN (kid "fv-dev1") — never the banking platform's dev1
    # pair: decoupling means separate keys, and a banking-sealed payload must
    # never open here. The public half is bundled in the app (ml/seal.ts).
    # Rotates at first real deployment; env override may use literal "\n" escapes.
    seal_private_key_pem: str | None = """-----BEGIN PRIVATE KEY-----
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
sjV5z6EPiOahKjJ6yBbRrxw=
-----END PRIVATE KEY-----"""

    # Cosine-similarity threshold for a `verified` verdict.
    match_threshold: float = 0.6

    # Verification attempt cap: max failed attempts per national_id per window.
    verify_max_attempts: int = 5
    verify_window_seconds: int = 600


@lru_cache
def get_settings() -> Settings:
    return Settings()
