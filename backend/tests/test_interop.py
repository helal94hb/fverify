"""Cross-language interop proof — the APP's JS seal must open HERE.

The app's __tests__/interop.test.ts seals the deterministic stub embedding
through the REAL seal.ts (node-forge, RSA-OAEP-SHA-256, enc1: envelope) and
writes the envelope + the source vector into tests/fixtures/. This test
unseals the envelope with THIS service's private key, dequantizes the compact
wire encoding, and asserts the cosine match against the source vector is ~1.0.
If the JS and python implementations of the envelope ever drift, this fails.

The fixtures regenerate whenever the app suite runs; they are vendored so this
test runs standalone. Skips (loudly) only if the app suite never produced them.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from app import match, seal
from app.api import _decode_compact_wire
from app.config import get_settings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.skipif(
    not (FIXTURES / "interop-envelope.txt").exists(),
    reason="app suite has not produced the interop fixtures",
)
def test_the_apps_js_envelope_unseals_and_matches_here():
    envelope = (FIXTURES / "interop-envelope.txt").read_text().strip()
    source = json.loads((FIXTURES / "interop-vector.json").read_text())

    pem = get_settings().seal_private_key_pem
    assert pem is not None
    private_key = serialization.load_pem_private_key(pem.encode(), password=None)

    plaintext = seal.unseal_envelope(envelope, private_key)
    decoded = _decode_compact_wire(plaintext)

    assert len(decoded) == len(source) == 128
    #: quantization costs precision — the decoded vector must sit within a
    #: tight distance of the source, and cosine self-match must be ~1.0
    score = match.cosine_similarity(decoded, source)
    assert score > 0.99, f"the wire round-trip must preserve the vector (got {score})"
    assert match.verdict_for(score, get_settings().match_threshold) == "verified"
