"""Test fixtures: temp-dir DB (never the repo file), fresh keys per test run."""

import base64
import json
import os
from dataclasses import dataclass

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app
from app.otp_export import decrypt_otp_export
from app.seal import b64url_encode


def seal_payload(public_key: rsa.RSAPublicKey, payload) -> str:
    """Client-side sealer (test double for the mobile app): enc1 envelope."""
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    ct = public_key.encrypt(json.dumps(payload).encode(), oaep)
    envelope = {"v": 1, "alg": "RSA-OAEP-SHA-256", "k": "test-key", "ct": b64url_encode(ct)}
    return "enc1:" + base64.urlsafe_b64encode(json.dumps(envelope).encode()).rstrip(b"=").decode()


def seal_string(public_key: rsa.RSAPublicKey, plaintext: str) -> str:
    """Seal a plain string (e.g. an OTP code) into an enc1: envelope."""
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    ct = public_key.encrypt(plaintext.encode("utf-8"), oaep)
    envelope = {"v": 1, "alg": "RSA-OAEP-SHA-256", "k": "test-key", "ct": b64url_encode(ct)}
    return "enc1:" + base64.urlsafe_b64encode(json.dumps(envelope).encode()).rstrip(b"=").decode()


@dataclass
class Harness:
    client: TestClient
    public_key: rsa.RSAPublicKey
    at_rest_key: str
    otp_export_key: str
    db_path: str

    def seal(self, payload) -> str:
        """Seal a JSON payload (embedding vector) into an enc1: envelope."""
        return seal_payload(self.public_key, payload)

    def seal_otp(self, code: str) -> str:
        """Seal a plain-text OTP code into an enc1: envelope (mobile app sim)."""
        return seal_string(self.public_key, code)

    def decrypt_otp(self, ciphered_otp: str) -> str:
        """Decrypt an aes256gcm: token (Agentys Code Execution Node sim)."""
        return decrypt_otp_export(ciphered_otp, self.otp_export_key)


@pytest.fixture()
def harness(tmp_path, monkeypatch) -> Harness:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    at_rest_key = Fernet.generate_key().decode()
    otp_export_key = base64.b64encode(os.urandom(32)).decode()
    db_path = str(tmp_path / "face-verify-test.db")

    monkeypatch.setenv("FV_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("FV_AT_REST_KEY", at_rest_key)
    monkeypatch.setenv("FV_SEAL_PRIVATE_KEY_PEM", pem)
    monkeypatch.setenv("FV_OTP_EXPORT_KEY", otp_export_key)
    get_settings.cache_clear()

    with TestClient(create_app()) as client:
        yield Harness(
            client=client,
            public_key=private_key.public_key(),
            at_rest_key=at_rest_key,
            otp_export_key=otp_export_key,
            db_path=db_path,
        )

    get_settings.cache_clear()
