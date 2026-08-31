"""Test fixtures: temp-dir DB (never the repo file), fresh keys per test run."""

import base64
import json
from dataclasses import dataclass

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app
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


@dataclass
class Harness:
    client: TestClient
    public_key: rsa.RSAPublicKey
    at_rest_key: str
    db_path: str

    def seal(self, payload) -> str:
        return seal_payload(self.public_key, payload)


@pytest.fixture()
def harness(tmp_path, monkeypatch) -> Harness:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    at_rest_key = Fernet.generate_key().decode()
    db_path = str(tmp_path / "face-verify-test.db")

    monkeypatch.setenv("FV_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("FV_AT_REST_KEY", at_rest_key)
    monkeypatch.setenv("FV_SEAL_PRIVATE_KEY_PEM", pem)
    get_settings.cache_clear()

    with TestClient(create_app()) as client:
        yield Harness(client=client, public_key=private_key.public_key(),
                      at_rest_key=at_rest_key, db_path=db_path)

    get_settings.cache_clear()
