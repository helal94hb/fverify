"""Independent implementation of the `enc1:` sealed-envelope FORMAT.

Envelope:  "enc1:" + base64url(JSON {"v":1, "alg":"RSA-OAEP-SHA-256",
           "k":"<key id>", "ct": base64url(ciphertext)})
Crypto:    RSA-OAEP with MGF1-SHA-256 (SHA-256 for both OAEP and MGF1 hashes).

The semantics are shared with the banking platform as a FORMAT only. This code
is a deliberate, decoupled copy — it imports nothing from the banking repos.

Known constraint (honest limit): plain RSA-OAEP caps the plaintext at
key_size/8 - 66 bytes (190 bytes with a 2048-bit key). That covers the compact
float vectors used in this phase; a production-grade embedding dimension would
need a hybrid (RSA-wrapped AES) envelope, which is a FORMAT change and must be
ratified by the Architect before adoption — not silently extended here.
"""

import base64
import binascii
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ALG = "RSA-OAEP-SHA-256"
VERSION = 1
PREFIX = "enc1:"


class SealError(Exception):
    """Raised when an envelope cannot be unsealed. Message is client-safe."""


def _b64url_decode(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError) as exc:
        raise SealError("malformed base64url in sealed envelope") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unseal_envelope(token: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt an `enc1:` envelope and return the plaintext bytes.

    Fail-closed: any structural or cryptographic problem raises SealError.
    """
    if not isinstance(token, str) or not token.startswith(PREFIX):
        raise SealError("payload is not sealed (expected an 'enc1:' envelope)")

    try:
        envelope = json.loads(_b64url_decode(token[len(PREFIX) :]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SealError("sealed envelope is not valid JSON") from exc

    if not isinstance(envelope, dict):
        raise SealError("sealed envelope is not a JSON object")
    if envelope.get("v") != VERSION:
        raise SealError("unsupported sealed-envelope version")
    if envelope.get("alg") != ALG:
        raise SealError("unsupported sealed-envelope algorithm")
    if not isinstance(envelope.get("k"), str) or not envelope["k"]:
        raise SealError("sealed envelope is missing its key id")
    ct = envelope.get("ct")
    if not isinstance(ct, str) or not ct:
        raise SealError("sealed envelope is missing its ciphertext")

    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    try:
        return private_key.decrypt(_b64url_decode(ct), oaep)
    except ValueError as exc:
        raise SealError("sealed ciphertext could not be decrypted") from exc
