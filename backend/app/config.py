"""Environment-driven settings for the standalone face-verification backend.

All settings use the ``FV_`` env prefix. This service is fully decoupled from
the digital-banking platform: its own database, its own keys, its own config.

DEV-DEFAULT SECRETS FAIL CLOSED. Every secret below ships with a working dev
default so a bare checkout runs — and each of those defaults is in the git
history. A production container that forgets to set one would otherwise seal
face templates and credentials with a key anyone can read, silently. So
`get_settings()` REFUSES TO START when any guarded secret is still its dev
default, unless `FV_ALLOW_DEV_DEFAULTS=true` is set (local dev and tests). The
guard fails closed on purpose: safety you have to remember to switch on is
safety you will forget on the one deploy that matters.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# DEV-ONLY Fernet key so a bare checkout runs out of the box.
# Any real deployment MUST set FV_AT_REST_KEY (a fresh `Fernet.generate_key()`).
# Rotating/changing it makes previously stored embeddings unreadable.
_DEV_ONLY_AT_REST_KEY = "6Mn63B3HGwFzFOVl6czGyPlDbzMDyCt9PyvTIEy0dxE="


#: The BANK's dev PUBLIC key — the public half only, so nothing secret lives
#: here. It is the address a verified identity's name is sealed to; the bank
#: holds the private half and is the only party that can read it.
_BANK_DEV_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA556h6DOi2H8x0mUkP11Y
wPZJeIkHEdctOgtgH6XxPgM+UKE5f9amr1MDR/mJrFnu7flxyIEqbIA4vwN9fxgh
U27HefkMvp0pVj5ELw4d91OyGffcp6dxEOkUHIcWpwupzR7FcertcG3kJvYNAuej
brYIkgKYjQBa+ENQ4v81b11QbZN9Ppjl7AJ8aEU/o3k5QL0dnWPbxofQYqNOmyyg
0H5ZQtUNbep6YG3h8jQxlslWMUloPwjCTN0ZE47Ph4lVjvOGb/LZt0Xr3wGFP7z6
XST35NgMkFevxfBa43DMm1kkBtgoM5q29ibV22gEL5NuWiM9QbkTWeameY5w/Ggr
RxVP0K77ZXSiHP2wCxp4brNqBoDsgDg4lbevzS8gQTscNcg9rTzMLc6DAL6X9pTl
61TwsFyLXUANkNubygYK6WkJ3UBBKdqRkfnvLRw1105J1J8FTrsBsngufUCifUWL
A8sqfkc9l2KP6fD3NjuIDyO+2XCbYA1rumgS61UpBqrdAgMBAAE=
-----END PUBLIC KEY-----"""


# DEV-ONLY private key used to unseal `enc1:` envelopes (kid "fv-dev1"). This
# app's OWN dev pair, never the banking platform's. Any real deployment MUST set
# FV_SEAL_PRIVATE_KEY_PEM; env override may use literal "\n" escapes.
_DEV_ONLY_SEAL_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
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
sjV5z6EPiOahKjJ6yBbRrxw=
-----END PRIVATE KEY-----"""

#: DEV-ONLY salt for one-time-secret hashing. A real deployment sets FV_OTP_HASH_SALT.
_DEV_ONLY_OTP_HASH_SALT = "fv-dev-only-salt"

#: DEV-ONLY AES-256-GCM key for OTPs exported to Agentys, base64 of 32 bytes.
#: A real deployment MUST set FV_OTP_EXPORT_KEY.
_DEV_ONLY_OTP_EXPORT_KEY = "dGhpcy1pcy1hLWRldi1vbmx5LWtleS0zMmJ5dGVzISE="


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FV_", env_file=".env", extra="ignore")

    # This service's OWN database file. Never the banking database.
    database_url: str = "sqlite+aiosqlite:///./face-verify.db"

    #: Escape hatch for local dev and tests: permits the dev-default secrets
    #: below. OFF by default so a real deployment fails closed — see the module
    #: docstring and `_assert_secrets_are_real`.
    allow_dev_defaults: bool = False

    # Fernet key for at-rest encryption of stored embeddings.
    at_rest_key: str = _DEV_ONLY_AT_REST_KEY

    # PEM RSA private key used to unseal `enc1:` envelopes. The DEV pair is this
    # app's OWN (kid "fv-dev1") — never the banking platform's dev1 pair: a
    # banking-sealed payload must never open here. Public half bundled in the app.
    seal_private_key_pem: str | None = _DEV_ONLY_SEAL_PRIVATE_KEY_PEM

    # Cosine-similarity threshold for a `verified` verdict (owner ruling
    # 2026-08-31: 0.80).
    match_threshold: float = 0.8

    #: How long a verification challenge stays usable. Short on purpose: it only
    #: has to cover one capture-and-submit, and every extra second is window for
    #: a relay attack.
    verify_challenge_ttl_seconds: int = 120

    #: 1:N DEDUPLICATION. Search each new face against the enrolled gallery
    #: before accepting it, so one person cannot hold two identities.
    #: `customer_id` cannot catch this case: the fraud is one HUMAN using two
    #: different identity documents, and only the biometric links them.
    dedup_enabled: bool = True

    #: Deliberately ABOVE the 0.8 verification threshold. Dedup errs toward
    #: precision because a false positive blocks a real customer at the last
    #: step of onboarding, while a false negative is caught later by review.
    #: Tuning this is a risk decision, not an engineering one.
    dedup_threshold: float = 0.85

    # Verification attempt cap: max failed attempts per username per window
    # (owner ruling 2026-08-31: 3 retries, then the lockout).
    verify_max_attempts: int = 3
    verify_window_seconds: int = 600

    # --- fverify's own OTP (owner ruling 2026-08-31 — this service mints ----
    # and verifies; dispatch rides the SMS seam, dev stub until a provider
    # or the Agentys SMS workflow lands).
    #: OFF = the fixed dev code "123456" is minted (lane/demo); ON = a real
    #: random code per send.
    otp_live: bool = False
    otp_stub_code: str = "123456"
    otp_ttl_seconds: int = 600
    otp_max_verify_attempts: int = 5
    otp_resend_cooldown_seconds: int = 60
    #: salt for one-time-secret hashing (env-overridden per environment)
    otp_hash_salt: str = _DEV_ONLY_OTP_HASH_SALT

    # AES-256-GCM key for encrypting OTPs exported to Agentys.
    # Must be a 32-byte key, base64-encoded. Generate with:
    #   python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
    otp_export_key: str = _DEV_ONLY_OTP_EXPORT_KEY

    #: THE BANK'S PUBLIC KEY — where a verified identity's NAME is sealed. In
    #: production this MUST be the real bank's public key: left at the dev
    #: default, verified names seal to a keypair whose private half sits in the
    #: BFF repo, so the sealed subject could be opened by anyone holding it.
    #: A wrong key means the bank cannot open the name and refuses the sign-in,
    #: which is the correct direction for that to fail in.
    bank_public_key_pem: str = _BANK_DEV_PUBLIC_KEY
    bank_key_id: str = "bank-dev1"


#: Secrets that must never run on their dev default in production. Each maps the
#: setting name to the exact dev value the guard compares against. `bank_key_id`
#: is a label, not a secret, so it is not guarded.
_GUARDED_DEV_DEFAULTS: dict[str, str] = {
    "at_rest_key": _DEV_ONLY_AT_REST_KEY,
    "seal_private_key_pem": _DEV_ONLY_SEAL_PRIVATE_KEY_PEM,
    "otp_hash_salt": _DEV_ONLY_OTP_HASH_SALT,
    "otp_export_key": _DEV_ONLY_OTP_EXPORT_KEY,
    "bank_public_key_pem": _BANK_DEV_PUBLIC_KEY,
}


def _assert_secrets_are_real(settings: Settings) -> None:
    """Refuse to run on dev-default secrets unless explicitly allowed.

    Fails closed: a deployment that sets no keys stops here rather than silently
    encrypting face templates and credentials with keys that are in the git
    history. `FV_ALLOW_DEV_DEFAULTS=true` opts local dev and tests back in.
    """
    if settings.allow_dev_defaults:
        return
    offenders = [
        f"FV_{name.upper()}"
        for name, dev_value in _GUARDED_DEV_DEFAULTS.items()
        if getattr(settings, name) == dev_value
    ]
    if offenders:
        raise RuntimeError(
            "fverify refuses to start: these secrets are still their DEV DEFAULTS "
            "(published in the repository): " + ", ".join(sorted(offenders)) + ". "
            "Set real values for each, or set FV_ALLOW_DEV_DEFAULTS=true for local "
            "development and tests."
        )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    _assert_secrets_are_real(settings)
    return settings
