/**
 * Seal envelope — shape, key id, and real RSA-OAEP-SHA-256 round-trip against
 * a throwaway key pair generated in-test (proving the crypto semantics, not
 * just the string shape). No key material in the repo beyond the marked dev
 * placeholder public key.
 */

import forge from 'node-forge';
import { DEV_PUBLIC_KEY_PEM, SEAL_KEY_ID, isSealed, seal } from '../src/ml/seal';
import {
  EMBEDDING_DIM,
  createStubEmbedding,
  decodeEmbeddingFromWire,
  encodeEmbeddingForWire,
} from '../src/ml/embedding';

function base64urlDecode(input: string): string {
  return forge.util.decode64(input.replace(/-/g, '+').replace(/_/g, '/'));
}

function parseEnvelope(payload: string): { v: number; alg: string; k: string; ct: string } {
  expect(payload.startsWith('enc1:')).toBe(true);
  const json = base64urlDecode(payload.slice('enc1:'.length));
  return JSON.parse(json);
}

describe('enc1 seal envelope', () => {
  it('carries the enc1: prefix and is detectable', () => {
    const sealed = seal('{"hello":"world"}');
    expect(sealed.startsWith('enc1:')).toBe(true);
    expect(isSealed(sealed)).toBe(true);
    expect(isSealed('{"hello":"world"}')).toBe(false);
    expect(isSealed(null)).toBe(false);
  });

  it('parses to the v1 RSA-OAEP-SHA-256 envelope with compact JSON in key order', () => {
    const sealed = seal('plaintext');
    const rawJson = base64urlDecode(sealed.slice('enc1:'.length));

    // Byte-for-byte contract with the python envelope: compact separators,
    // keys exactly in v, alg, k, ct order.
    expect(rawJson.startsWith('{"v":1,"alg":"RSA-OAEP-SHA-256","k":"')).toBe(true);
    expect(rawJson.endsWith('}')).toBe(true);

    const env = parseEnvelope(sealed);
    expect(env.v).toBe(1);
    expect(env.alg).toBe('RSA-OAEP-SHA-256');
    expect(env.ct.length).toBeGreaterThan(0);
    // ct is base64url — url-safe alphabet only (padding '=' kept, python-style).
    expect(env.ct).toMatch(/^[A-Za-z0-9_-]+=*$/);
  });

  it('carries the bundled key id by default and honors an explicit key id', () => {
    expect(parseEnvelope(seal('x')).k).toBe(SEAL_KEY_ID);
    expect(parseEnvelope(seal('x', DEV_PUBLIC_KEY_PEM, 'dev2')).k).toBe('dev2');
    expect(SEAL_KEY_ID).toBe('fv-dev1');
  });

  it('round-trips through RSA-OAEP with SHA-256 and MGF1-SHA-256', () => {
    const pair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
    const publicPem = forge.pki.publicKeyToPem(pair.publicKey);
    const plaintext = 'the quick brown fox';

    const sealed = seal(plaintext, publicPem, 'test-key');
    const env = parseEnvelope(sealed);
    expect(env.k).toBe('test-key');

    const ct = base64urlDecode(env.ct);
    const opened = pair.privateKey.decrypt(ct, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
      mgf1: forge.mgf.mgf1.create(forge.md.sha256.create()),
    });
    expect(forge.util.decodeUtf8(opened)).toBe(plaintext);
  });

  it('produces different ciphertext for the same plaintext (OAEP semantic security)', () => {
    expect(seal('same')).not.toBe(seal('same'));
  });

  it('rejects a plaintext that cannot fit a single OAEP block', () => {
    // 2048-bit key → 190-byte OAEP-SHA-256 ceiling; fail closed, never truncate.
    const pair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
    const publicPem = forge.pki.publicKeyToPem(pair.publicKey);
    expect(() => seal('x'.repeat(1000), publicPem)).toThrow();
  });
});

describe('embedding wire encoding (the seal plaintext)', () => {
  it('encodes a 128-dim unit embedding to compact base64 that fits the OAEP block', () => {
    const embedding = createStubEmbedding('wire-check');
    const encoded = encodeEmbeddingForWire(embedding);
    // 128 int8 bytes → 172 base64 chars (with padding) — well under the
    // 190-byte ceiling of even a 2048-bit OAEP-SHA-256 block.
    expect(encoded).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(encoded.length).toBe(172);

    // And the full envelope round-trips with the bundled dev key.
    const sealed = seal(JSON.stringify(encoded));
    expect(isSealed(sealed)).toBe(true);
  });

  it('round-trips through quantization within int8 tolerance', () => {
    const embedding = createStubEmbedding('round-trip');
    const decoded = decodeEmbeddingFromWire(encodeEmbeddingForWire(embedding));
    expect(decoded).toHaveLength(EMBEDDING_DIM);
    for (let i = 0; i < EMBEDDING_DIM; i++) {
      expect(Math.abs(decoded[i]! - embedding[i]!)).toBeLessThanOrEqual(1 / 127 + 1e-9);
    }
  });

  it('fails closed on a wrong-sized embedding', () => {
    expect(() => encodeEmbeddingForWire([0.1, 0.2])).toThrow();
  });

  it('stub embeddings are deterministic and unit-length', () => {
    const a = createStubEmbedding('same-seed');
    const b = createStubEmbedding('same-seed');
    const c = createStubEmbedding('other-seed');
    expect(a).toEqual(b);
    expect(a).not.toEqual(c);
    expect(a).toHaveLength(EMBEDDING_DIM);
    const norm = Math.sqrt(a.reduce((s, v) => s + v * v, 0));
    expect(norm).toBeCloseTo(1, 6);
  });
});
