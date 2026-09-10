"""Independent implementation of the sealed-envelope FORMAT — `enc1:` and `enc2:`.

enc1  "enc1:" + base64url(JSON {"v":1, "alg":"RSA-OAEP-SHA-256",
                                "k":"<key id>", "ct": base64url(ciphertext)})
      Crypto: RSA-OAEP, MGF1-SHA-256 (SHA-256 for both OAEP and MGF1 hashes).

enc2  "enc2:" + base64url(JSON {"v":2, "alg":"RSA-OAEP-SHA-256+A256GCM",
                                "k":"<key id>",
                                "ek": base64url(RSA-OAEP-wrapped 256-bit key),
                                "iv": base64url(96-bit nonce),
                                "ct": base64url(AES-256-GCM ciphertext||tag)})
      A fresh content key per envelope; the key id is bound as AES-GCM
      additional data, so an envelope cannot be replayed under a different key
      id without the tag failing.

The semantics are shared with the banking platform as a FORMAT only. This code
is a deliberate, decoupled copy — it imports nothing from the banking repos.

WHY enc2 EXISTS (owner ruling 2026-09-10)
    Plain RSA-OAEP caps the plaintext at key_size/8 - 66 bytes — 318 bytes on
    the RSA-3072 key this service runs. Two encodings already live under that
    ceiling and it is worth being exact about which sizes actually fit, because
    the interesting cases are the ones that do not:

      dims   JSON floats   int8 compact (b64)   fits enc1 @318B
       128        1.3 KB              172 B     yes, compact only
       256        2.7 KB              344 B     no
       512        5.3 KB              684 B     no

    So `_decode_compact_wire` already buys 128 dimensions, and a bigger RSA key
    does not buy the next step (RSA-4096 gives 446 bytes, still short of 256
    dims). An ArcFace-class 512-dim vector is 2.2x over the ceiling even
    quantized to one byte per dimension, and no encoding trick closes that.

    Sizing the vector DOWN to fit is the alternative, and it is the worse one:
    the same envelope is used by /verifications at TRANSACTION time, so the
    envelope would be silently bounding the accuracy of every future face check
    against a payment. A short embedding scored against a 0.8 cosine threshold
    matches far more of the population than a full one.

    enc1 is NOT deprecated. The credential and the OTP are small, fit
    comfortably, and have no reason to carry a wrapped key.
"""

import base64
import binascii
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALG = "RSA-OAEP-SHA-256"
VERSION = 1
PREFIX = "enc1:"

ALG_HYBRID = "RSA-OAEP-SHA-256+A256GCM"
VERSION_HYBRID = 2
PREFIX_HYBRID = "enc2:"

#: 256-bit content key, 96-bit nonce — the AES-GCM sizes with the widest
#: interoperable support (WebCrypto and node-forge both default to a 96-bit IV).
CONTENT_KEY_BYTES = 32
NONCE_BYTES = 12


class SealError(Exception):
    """Raised when an envelope cannot be unsealed. Message is client-safe."""


def _b64url_decode(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError) as exc:
        raise SealError("malformed base64url in sealed envelope") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _parse(token: str, prefix: str, version: int, alg: str) -> dict:
    """Shared structural checks. Fail-closed on every branch."""
    try:
        envelope = json.loads(_b64url_decode(token[len(prefix):]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SealError("sealed envelope is not valid JSON") from exc

    if not isinstance(envelope, dict):
        raise SealError("sealed envelope is not a JSON object")
    if envelope.get("v") != version:
        raise SealError("unsupported sealed-envelope version")
    if envelope.get("alg") != alg:
        raise SealError("unsupported sealed-envelope algorithm")
    if not isinstance(envelope.get("k"), str) or not envelope["k"]:
        raise SealError("sealed envelope is missing its key id")
    ct = envelope.get("ct")
    if not isinstance(ct, str) or not ct:
        raise SealError("sealed envelope is missing its ciphertext")
    return envelope


def unseal_envelope(token: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt an `enc1:` or `enc2:` envelope and return the plaintext bytes.

    Fail-closed: any structural or cryptographic problem raises SealError.

    Dispatch is on the PREFIX, and an unknown prefix is refused rather than
    guessed at — a payload that is not sealed must never be read as one.
    """
    if not isinstance(token, str):
        raise SealError("payload is not sealed (expected a sealed envelope)")

    if token.startswith(PREFIX_HYBRID):
        return _unseal_hybrid(token, private_key)
    if token.startswith(PREFIX):
        envelope = _parse(token, PREFIX, VERSION, ALG)
        try:
            return private_key.decrypt(_b64url_decode(envelope["ct"]), _oaep())
        except ValueError as exc:
            raise SealError("sealed ciphertext could not be decrypted") from exc

    raise SealError("payload is not sealed (expected an 'enc1:' or 'enc2:' envelope)")


def envelope_nonce(token: str) -> str | None:
    """The challenge nonce an enc2 envelope claims, WITHOUT decrypting it.

    The server needs this before it can look the challenge up, so it travels in
    the clear -- but it is also folded into the AES-GCM additional data, so a
    replayer who swaps it for a fresh nonce breaks the tag. Readable, not
    forgeable.
    """
    if not isinstance(token, str) or not token.startswith(PREFIX_HYBRID):
        return None
    try:
        envelope = json.loads(_b64url_decode(token[len(PREFIX_HYBRID):]))
    except (json.JSONDecodeError, UnicodeDecodeError, SealError):
        return None
    n = envelope.get("n") if isinstance(envelope, dict) else None
    return n if isinstance(n, str) and n else None


def _aad(key_id: str, nonce: str | None) -> bytes:
    """What the tag authenticates. `|` cannot appear in a base64url nonce or in
    a key id, so the two fields cannot be shifted across the separator."""
    return (f"{key_id}|{nonce}" if nonce else key_id).encode("utf-8")


def _unseal_hybrid(token: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """enc2: RSA-OAEP unwraps a content key; AES-256-GCM opens the payload."""
    envelope = _parse(token, PREFIX_HYBRID, VERSION_HYBRID, ALG_HYBRID)

    for field in ("ek", "iv"):
        if not isinstance(envelope.get(field), str) or not envelope[field]:
            raise SealError(f"sealed envelope is missing its {field}")

    try:
        content_key = private_key.decrypt(_b64url_decode(envelope["ek"]), _oaep())
    except ValueError as exc:
        raise SealError("sealed content key could not be unwrapped") from exc

    #: Length is checked explicitly. Accepting a short key would let a caller
    #: pick the strength of the cipher protecting the payload.
    if len(content_key) != CONTENT_KEY_BYTES:
        raise SealError("sealed content key is the wrong length")

    nonce = _b64url_decode(envelope["iv"])
    if len(nonce) != NONCE_BYTES:
        raise SealError("sealed envelope nonce is the wrong length")

    try:
        #: The key id AND the challenge nonce are authenticated, not merely
        #: carried. Rewriting either breaks the tag rather than silently
        #: producing an envelope that looks addressed elsewhere or fresh.
        return AESGCM(content_key).decrypt(
            nonce,
            _b64url_decode(envelope["ct"]),
            _aad(envelope["k"], envelope.get("n")),
        )
    except InvalidTag as exc:
        raise SealError("sealed payload failed authentication") from exc


def seal_hybrid(
    plaintext: bytes,
    public_key: rsa.RSAPublicKey,
    key_id: str,
    nonce: str | None = None,
) -> str:
    """Produce an `enc2:` envelope. Present so the format has ONE definition
    that both the tests and any Python caller share — the apps implement the
    same shape in TypeScript, and `tests/test_interop.py` is what holds the two
    honest."""
    content_key = os.urandom(CONTENT_KEY_BYTES)
    iv = os.urandom(NONCE_BYTES)          # the AES-GCM IV, not the challenge
    ciphertext = AESGCM(content_key).encrypt(iv, plaintext, _aad(key_id, nonce))
    body = {
            "v": VERSION_HYBRID,
            "alg": ALG_HYBRID,
            "k": key_id,
            "ek": b64url_encode(public_key.encrypt(content_key, _oaep())),
            "iv": b64url_encode(iv),
            "ct": b64url_encode(ciphertext),
    }
    if nonce:
        body["n"] = nonce
    envelope = json.dumps(body, separators=(",", ":"))
    return PREFIX_HYBRID + b64url_encode(envelope.encode("utf-8"))
