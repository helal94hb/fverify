/**
 * CROSS-LANGUAGE INTEROP PROOF — the app's seal must open on the backend.
 *
 * The app seals with node-forge (JS) and the backend unseals with
 * cryptography (python). This test seals the deterministic stub embedding
 * through the REAL seal.ts + embedding.ts and writes the envelope + the
 * source vector to the backend's test fixtures; the backend's
 * test_interop.py unseals it, dequantizes it, and asserts the cosine match
 * is ~1.0. If the two implementations ever drift, that test fails.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { createStubEmbedding, encodeEmbeddingForWire } from '../src/ml/embedding';
import { seal, sealHybrid } from '../src/ml/seal';

const FIXTURE_DIR = join(__dirname, '..', '..', 'backend', 'tests', 'fixtures');

describe('interop fixture producer (JS seal → python unseal)', () => {
  it('seals the known vector and writes the backend fixture pair', () => {
    const vector = createStubEmbedding('interop-fixture-v1');
    const wire = encodeEmbeddingForWire(vector);
    const envelope = seal(wire);

    mkdirSync(FIXTURE_DIR, { recursive: true });
    writeFileSync(join(FIXTURE_DIR, 'interop-envelope.txt'), envelope);
    writeFileSync(join(FIXTURE_DIR, 'interop-vector.json'), JSON.stringify(vector));

    // self-check in JS land before handing over
    expect(envelope.startsWith('enc1:')).toBe(true);
    expect(wire).toHaveLength(172);
  });

  it('seals a 512-dim vector through enc2 and writes that fixture too', () => {
    // The dimension enc1 CANNOT carry: 512 bytes quantized -> ~684 b64 chars
    // against a 318-byte ceiling. This is the case the hybrid envelope exists
    // for, so it is the case the interop proof must cover.
    const big = Array.from({ length: 512 }, (_, i) => Math.sin(i * 0.13));
    const norm = Math.sqrt(big.reduce((a, v) => a + v * v, 0));
    const unit = big.map((v) => v / norm);

    const quantized = Uint8Array.from(unit, (v) =>
      Math.round(Math.max(-1, Math.min(1, v)) * 127) & 0xff,
    );
    const wire = Buffer.from(quantized).toString('base64');
    const envelope = sealHybrid(wire);

    writeFileSync(join(FIXTURE_DIR, 'interop-envelope-enc2.txt'), envelope);
    writeFileSync(join(FIXTURE_DIR, 'interop-vector-enc2.json'), JSON.stringify(unit));

    expect(envelope.startsWith('enc2:')).toBe(true);
    expect(wire.length).toBeGreaterThan(318);   // would not fit enc1
  });
});
