"""AES-256-GCM encryption for OTP export to Agentys (transit encryption).

The OTP is minted and hashed (at-rest) inside fverify. This module encrypts
the PLAINTEXT code into a compact token that only the Agentys Code Execution
Node can decrypt (using the shared symmetric key FV_OTP_EXPORT_KEY).

Token format:  aes256gcm:<base64url(12-byte-nonce || ciphertext || 16-byte-tag)>

The raw code MUST be discarded from memory immediately after this call.
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "aes256gcm:"


class OtpExportError(Exception):
    """Raised when an export token cannot be decrypted. Message is client-safe."""


def _decode_key(key_b64: str) -> bytes:
    """Decode a base64-encoded 32-byte AES-256 key. Fail-closed."""
    try:
        raw = base64.b64decode(key_b64)
    except Exception as exc:
        raise OtpExportError("OTP export key is not valid base64") from exc
    if len(raw) != 32:
        raise OtpExportError(
            f"OTP export key must be 32 bytes (got {len(raw)})"
        )
    return raw


def encrypt_otp_for_export(code: str, key_b64: str) -> str:
    """AES-256-GCM encrypt the OTP code for Agentys.

    Returns a compact string: ``aes256gcm:<base64url(nonce|ct|tag)>``.
    The nonce is a cryptographically random 96-bit value (NIST SP 800-38D).
    """
    key = _decode_key(key_b64)
    nonce = os.urandom(12)  # 96-bit, NIST recommendation for GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, code.encode("utf-8"), None)
    # ct already includes the 16-byte authentication tag (appended by AESGCM)
    payload = base64.urlsafe_b64encode(nonce + ct).rstrip(b"=").decode("ascii")
    return f"{PREFIX}{payload}"


def decrypt_otp_export(token: str, key_b64: str) -> str:
    """Decrypt an ``aes256gcm:`` token and return the plaintext OTP code.

    Fail-closed: any structural or cryptographic problem raises OtpExportError.
    """
    if not isinstance(token, str) or not token.startswith(PREFIX):
        raise OtpExportError("token is not an aes256gcm: export token")

    key = _decode_key(key_b64)
    b64_part = token[len(PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(b64_part + "=" * (-len(b64_part) % 4))
    except Exception as exc:
        raise OtpExportError("malformed base64url in export token") from exc

    # nonce = first 12 bytes; remainder = ciphertext + 16-byte tag
    if len(raw) < 12 + 1 + 16:
        raise OtpExportError("export token payload is too short")

    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, None)
    except Exception as exc:
        raise OtpExportError("export token decryption failed") from exc

    return plaintext.decode("utf-8")
