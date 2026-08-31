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
import { dirname, join } from 'node:path';

import { createStubEmbedding, encodeEmbeddingForWire } from '../src/ml/embedding';
import { seal } from '../src/ml/seal';

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
});
