"""At-rest encryption for stored embeddings (Fernet / AES-128-CBC + HMAC).

Embeddings are sealed in transit (enc1:) AND encrypted at rest. A raw database
read must only ever show ciphertext, never floats.
"""

import json

from cryptography.fernet import Fernet


def get_fernet(key: str) -> Fernet:
    """Build a Fernet instance from the configured key (fail-closed)."""
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(
            "FV_AT_REST_KEY is not a valid Fernet key (url-safe base64, 32 bytes)"
        ) from exc


def encrypt_embedding(embedding: list[float], fernet: Fernet) -> bytes:
    return fernet.encrypt(json.dumps(embedding).encode("utf-8"))


def decrypt_embedding(token: bytes, fernet: Fernet) -> list[float]:
    plaintext = fernet.decrypt(token)
    data = json.loads(plaintext)
    if not isinstance(data, list) or not all(isinstance(x, (int, float)) for x in data):
        raise RuntimeError("decrypted embedding payload is not a float vector")
    return [float(x) for x in data]
