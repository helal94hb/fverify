"""fverify refuses to boot on dev-default secrets, unless explicitly allowed.

Each secret ships with a working dev default, and every one of those defaults is
in the git history. A production container that forgets to set one would encrypt
face templates and unseal credentials with a key anyone can read — silently. The
guard makes that a loud refusal instead.

The tests are DISCRIMINATING: one proves the guard FIRES on a real dev default
(the negative control — without it a guard that never fires would pass), one
proves it does NOT fire when every secret is real (so it is not just always
raising), and one proves the dev opt-in works.
"""

import base64
import os

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import _DEV_ONLY_AT_REST_KEY, get_settings


def _real_secrets(monkeypatch) -> None:
    """Set every guarded secret to a fresh, non-default value."""
    pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    pub = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    monkeypatch.setenv("FV_AT_REST_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("FV_SEAL_PRIVATE_KEY_PEM", pem)
    monkeypatch.setenv("FV_OTP_HASH_SALT", "a-real-per-env-salt")
    monkeypatch.setenv("FV_OTP_EXPORT_KEY", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("FV_BANK_PUBLIC_KEY_PEM", pub)


def test_refuses_to_boot_on_a_dev_default_secret(monkeypatch) -> None:
    """THE NEGATIVE CONTROL. Every secret real EXCEPT the at-rest key, which is
    left at its published default and NOT allowed — boot must refuse, and the
    message must name the offender."""
    _real_secrets(monkeypatch)
    monkeypatch.setenv("FV_AT_REST_KEY", _DEV_ONLY_AT_REST_KEY)  # the one bad one
    monkeypatch.delenv("FV_ALLOW_DEV_DEFAULTS", raising=False)
    get_settings.cache_clear()

    with pytest.raises(RuntimeError) as exc:
        get_settings()
    assert "FV_AT_REST_KEY" in str(exc.value)
    #: and it names ONLY the offender, not the secrets that were set correctly
    assert "FV_SEAL_PRIVATE_KEY_PEM" not in str(exc.value)
    get_settings.cache_clear()


def test_boots_when_every_secret_is_real(monkeypatch) -> None:
    """THE POSITIVE CONTROL. All secrets real, no allow flag — boot succeeds.
    Proves the guard is not simply always raising."""
    _real_secrets(monkeypatch)
    monkeypatch.delenv("FV_ALLOW_DEV_DEFAULTS", raising=False)
    get_settings.cache_clear()

    settings = get_settings()  # must not raise
    assert settings.allow_dev_defaults is False
    get_settings.cache_clear()


def test_dev_flag_permits_the_defaults(monkeypatch) -> None:
    """The escape hatch: a bare checkout with the flag on boots on dev defaults."""
    for var in (
        "FV_AT_REST_KEY",
        "FV_SEAL_PRIVATE_KEY_PEM",
        "FV_OTP_HASH_SALT",
        "FV_OTP_EXPORT_KEY",
        "FV_BANK_PUBLIC_KEY_PEM",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("FV_ALLOW_DEV_DEFAULTS", "true")
    get_settings.cache_clear()

    settings = get_settings()  # must not raise
    assert settings.at_rest_key == _DEV_ONLY_AT_REST_KEY
    get_settings.cache_clear()
