/**
 * The "enc1" seal — RSA-OAEP-SHA-256 envelope, pure JS via node-forge.
 *
 * This is an INDEPENDENT implementation of the envelope format the banking
 * platform already runs (owner ruling: semantics shared as a FORMAT, code
 * stays independent — nothing here imports or links to banking code).
 *
 * Envelope, byte-for-byte semantics (matched against the platform's python
 * implementation):
 *
 *     "enc1:" + base64url(JSON {"v":1,"alg":"RSA-OAEP-SHA-256","k":<key id>,
 *                                "ct": base64url(ciphertext)})
 *
 *   - JSON is compact (no spaces), keys in the order v, alg, k, ct.
 *   - base64url KEEPS "=" padding — python's base64.urlsafe_b64encode does
 *     not strip it, and byte-for-byte means byte-for-byte.
 *   - ciphertext is RSA-OAEP with SHA-256 as both the OAEP hash and the
 *     MGF1 hash, and an empty label (python: label=None).
 *   - "k" identifies the key pair so the backend can pick the right private
 *     key and rotation has somewhere to live.
 *
 * Single-block OAEP limits the plaintext size (key_bits/8 - 66 bytes), which
 * is why the embedding crosses the wire in the compact quantized encoding
 * from ./embedding.ts, not as a JSON float array. See encodeEmbeddingForWire.
 */

import forge from 'node-forge';

const PREFIX = 'enc1:';
const ALG = 'RSA-OAEP-SHA-256';

/** Key id the bundled dev key is registered under on the backend. */
export const SEAL_KEY_ID = 'fv-dev1';

/**
 * PLACEHOLDER dev public key — the public half of the "dev1" pair.
 *
 * The private half belongs to the standalone backend's dev config and NEVER
 * ships in the app. This freshly generated placeholder must be replaced with
 * the backend track's actual dev1 public key before any end-to-end run; a
 * sealed payload the backend cannot open fails closed, never silently.
 */
export const DEV_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA5JSOlbXMUyARC9gzdX0p
K9p8W9MONpYm4pf84WRCGE8sim5NI4SmVGnG7MmhK1ltDGOcvzfM3lnOwJHV2v0K
TLM1Ym40MZV0yFeBkZBpvLRyyEbU06bxbLHn5XX7XPs/98e/yjlQU8x+HYPID0iM
80oXO4dFc7s0Rjl7VyDq1L6iJTPcKePXupsVnL8m48LYBUCkuryau/CXyEIbs9Jc
c93T3HTUt8kNcceZoulibblne+4DVuJnNaMd6ocZvhUEwrGVsl9e/vYzf3Dpmcr5
vsOKB2/xqhIxUGMETwgBlwbcsIsGNKi75RB/lWyLxA0idhC0hc+dZm/+xE59QgFX
ImLR9z9VvUD/QgK48KcI8Db+1aJ4m/Kf4uGcNyyHPm+H7egswrPIqNnFrU/jnPSl
HdPKQonJE14H8GHq+6dFBcQpjTqHuM4/LeK3CcDWBtyw7oKguhuhqGwi/KAwVfTi
LMCVI6JPlS1K/tqnPio5bGa5XHh4DSqXluRFKwkhEoKZAgMBAAE=
-----END PUBLIC KEY-----`;

/** Detectable by construction — the receiver can tell sealed from cleartext. */
export function isSealed(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith(PREFIX);
}

/** base64url WITH padding, matching python's urlsafe_b64encode byte-for-byte. */
function base64url(binaryString: string): string {
  return forge.util
    .encode64(binaryString)
    .replace(/\r?\n/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Seal a UTF-8 JSON plaintext for transport. Only the embedding's compact
 * wire encoding is ever sealed in this app — no image, no PII, ever.
 */
export function seal(
  plaintextJson: string,
  publicKeyPem: string = DEV_PUBLIC_KEY_PEM,
  keyId: string = SEAL_KEY_ID,
): string {
  // Env-carried PEMs may have escaped newlines — accept both forms.
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem.replace(/\\n/g, '\n'));
  const ciphertext = publicKey.encrypt(forge.util.encodeUtf8(plaintextJson), 'RSA-OAEP', {
    md: forge.md.sha256.create(),
    mgf1: forge.mgf.mgf1.create(forge.md.sha256.create()),
  });
  const envelope = JSON.stringify({ v: 1, alg: ALG, k: keyId, ct: base64url(ciphertext) });
  return PREFIX + base64url(forge.util.encodeUtf8(envelope));
}
