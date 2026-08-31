/**
 * On-device embedding extraction — the ADAPTER between the camera pipeline and
 * the face model. This pass ships the interface plus a deterministic stub;
 * the real TFLite wiring lands next iteration.
 *
 * REAL MODEL WIRING POINT (documented, not implemented yet):
 *   1. Model file: a MobileFaceNet-class TFLite model lands at
 *      `assets/models/mobilefacenet.tflite` (declared in the app bundle, no
 *      download — the app must work fully on-device).
 *   2. Runner: `react-native-fast-tflite` (vision-camera frame-processor
 *      plugin) loads the model; the face crop comes from the vision-camera
 *      frame processor in the liveness screen (ML Kit face detection gives
 *      the bounding box on-device).
 *   3. The frame processor (a worklet) cannot call async JS directly — it
 *      posts the cropped face tensor via `runOnJS` into the injected
 *      `EmbeddingExtractor` implementation, which runs the model and returns
 *      the raw vector.
 *   4. NORMALIZATION (contract-critical): the raw model output MUST be
 *      L2-normalized to unit length here on-device (`l2Normalize` below)
 *      before sealing — the backend matches with cosine distance, which
 *      assumes unit vectors.
 *
 * SECURITY POSTURE: face IMAGES never leave the phone and are never stored —
 * the frame lives only inside the frame processor, the embedding is the only
 * thing that leaves, and it leaves sealed (see ./seal.ts).
 */

/** Opaque native frame handle — react-native-vision-camera's `Frame` in the real wiring. */
export type CameraFrame = unknown;

/** MobileFaceNet-class models produce 128-dimensional unit embeddings. */
export const EMBEDDING_DIM = 128;

/** The adapter contract every extractor (stub or real) implements. */
export interface EmbeddingExtractor {
  extractEmbedding(frame: CameraFrame): Promise<number[]>;
}

/** Unit length — required before the vector is sealed for the server-side cosine match. */
export function l2Normalize(vector: number[]): number[] {
  const norm = Math.sqrt(vector.reduce((sum, v) => sum + v * v, 0));
  if (norm === 0) {
    // Fail closed: a zero vector is not a face, and must never compare equal.
    throw new Error('cannot normalize a zero embedding');
  }
  return vector.map((v) => v / norm);
}

/**
 * Compact wire encoding (the seal plaintext) — NOT a JSON float array.
 *
 * RSA-OAEP seals a single block (for a 3072-bit key, 318 bytes max), and a
 * 128-dim JSON float array is ~2 KB. So the unit vector is quantized to one
 * signed byte per dimension (q = round(clamp(v, -1, 1) * 127), standard int8
 * embedding transport) and base64-encoded: exactly 172 characters for 128
 * dims, which fits the OAEP block with room to spare.
 *
 * The backend unseals → base64-decodes → dequantizes (q / 127) → cosine
 * against the stored embedding. This encoding is the app's half of the wire
 * contract; keep it in lockstep with the backend track.
 */
export function encodeEmbeddingForWire(embedding: number[]): string {
  if (embedding.length !== EMBEDDING_DIM) {
    // Fail closed: a malformed embedding must never be sealed and sent.
    throw new Error(`embedding must have ${EMBEDDING_DIM} dimensions, got ${embedding.length}`);
  }
  const bytes = embedding.map((v) => Math.round(Math.max(-1, Math.min(1, v)) * 127) & 0xff);
  return base64Encode(bytes);
}

/** Inverse of encodeEmbeddingForWire — used by tests and by any local sanity check. */
export function decodeEmbeddingFromWire(encoded: string): number[] {
  const bytes = base64Decode(encoded);
  return bytes.map((b) => ((b & 0x80 ? b - 256 : b) / 127));
}

function base64Encode(bytes: number[]): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out += alphabet[b0 >> 2];
    out += alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? alphabet[b2 & 0x3f] : '=';
  }
  return out;
}

function base64Decode(encoded: string): number[] {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const clean = encoded.replace(/=+$/, '');
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const c = [0, 1, 2, 3].map((k) => {
      const idx = i + k < clean.length ? alphabet.indexOf(clean[i + k]!) : 0;
      if (idx < 0) {
        throw new Error('invalid base64 in embedding wire encoding');
      }
      return idx;
    });
    bytes.push((c[0]! << 2) | (c[1]! >> 4));
    if (i + 2 < clean.length) bytes.push(((c[1]! & 0x0f) << 4) | (c[2]! >> 2));
    if (i + 3 < clean.length) bytes.push(((c[2]! & 0x03) << 6) | c[3]!);
  }
  return bytes;
}

/**
 * PRE-MODEL STAND-IN — deterministic stub, NOT a face model.
 *
 * Derives a stable pseudo-embedding from a seed string (FNV-1a hash →
 * mulberry32 PRNG → L2-normalized), so the enroll→verify pipeline is
 * exercisable end to end before the TFLite model lands. Same seed in, same
 * unit vector out — which is exactly what makes pipeline tests stable. It has
 * no biometric meaning whatsoever and must never be presented as one.
 */
export class StubEmbeddingExtractor implements EmbeddingExtractor {
  constructor(private readonly seed: string = 'stub-seed') {}

  extractEmbedding(frame: CameraFrame): Promise<number[]> {
    return Promise.resolve(createStubEmbedding(`${this.seed}:${String(frame)}`));
  }
}

/** Deterministic pseudo-embedding from a seed — test/pipeline scaffolding only. */
export function createStubEmbedding(seed: string): number[] {
  // FNV-1a 32-bit hash of the seed → mulberry32 PRNG state.
  let state = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    state ^= seed.charCodeAt(i);
    state = Math.imul(state, 0x01000193);
  }
  const next = (): number => {
    state = (state + 0x6d2b79f5) | 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const raw: number[] = [];
  for (let i = 0; i < EMBEDDING_DIM; i++) {
    raw.push(next() * 2 - 1);
  }
  return l2Normalize(raw);
}
