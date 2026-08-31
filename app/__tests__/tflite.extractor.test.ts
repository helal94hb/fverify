/**
 * TFLite embedding extractor — pure helpers (crop math, pixel normalization,
 * mailbox) and the extractor contract against an INJECTED fake model (the
 * real TensorflowModel is native; jest never loads it). No PII — synthetic
 * vectors only.
 */

import type { TensorflowModel } from 'react-native-fast-tflite';
import { EMBEDDING_DIM } from '../src/ml/embedding';
import {
  captureFaceCrop,
  clearFaceCrop,
  computeFaceCropRect,
  FACE_CROP_LENGTH,
  getLatestFaceCrop,
  normalizeFaceCrop,
  TfliteEmbeddingExtractor,
} from '../src/ml/tfliteExtractor';

/** A fake TensorflowModel returning a fixed raw (non-unit) vector. */
function fakeModel(output: number[]): TensorflowModel {
  return {
    delegate: 'default',
    inputs: [],
    outputs: [],
    run: (inputs: unknown[]) => {
      expect(inputs[0]).toHaveLength(FACE_CROP_LENGTH);
      return Promise.resolve([Float32Array.from(output)]);
    },
    runSync: () => {
      throw new Error('not used by the extractor');
    },
  } as unknown as TensorflowModel;
}

function syntheticCrop(fill = 0.5): Float32Array {
  return new Float32Array(FACE_CROP_LENGTH).fill(fill);
}

describe('computeFaceCropRect', () => {
  it('expands the face box into a square with margin, centered on the face', () => {
    const rect = computeFaceCropRect({ x: 100, y: 200, width: 80, height: 100 }, 720, 1280);
    // side = max(80,100) * 1.5 = 150; center (140, 250) → x=65, y=175
    expect(rect).toEqual({ x: 65, y: 175, width: 150, height: 150 });
  });

  it('clamps to frame bounds', () => {
    const rect = computeFaceCropRect({ x: 0, y: 0, width: 200, height: 200 }, 720, 1280);
    expect(rect.x).toBeGreaterThanOrEqual(0);
    expect(rect.y).toBeGreaterThanOrEqual(0);
    expect(rect.width).toBeLessThanOrEqual(720);
  });

  it('never exceeds the smaller frame dimension', () => {
    const rect = computeFaceCropRect({ x: 0, y: 0, width: 900, height: 900 }, 720, 1280);
    expect(rect.width).toBeLessThanOrEqual(720);
    expect(rect.height).toBeLessThanOrEqual(720);
  });
});

describe('normalizeFaceCrop', () => {
  it('maps [0..1] to [-1..1] by default (signed)', () => {
    const out = normalizeFaceCrop(Float32Array.from([0, 0.5, 1].concat(Array(FACE_CROP_LENGTH - 3).fill(0))));
    expect(out[0]).toBeCloseTo(-1);
    expect(out[1]).toBeCloseTo(0);
    expect(out[2]).toBeCloseTo(1);
  });

  it('zero-one mode passes values through', () => {
    const out = normalizeFaceCrop(syntheticCrop(0.25), 'zero-one');
    expect(out[0]).toBeCloseTo(0.25);
  });

  it('fails closed on a malformed tensor', () => {
    expect(() => normalizeFaceCrop(new Float32Array(10))).toThrow();
  });
});

describe('face-crop mailbox', () => {
  it('stores, returns, and clears the latest crop', () => {
    clearFaceCrop();
    expect(getLatestFaceCrop()).toBeNull();
    const crop = syntheticCrop();
    captureFaceCrop(crop);
    expect(getLatestFaceCrop()).toBe(crop);
    clearFaceCrop();
    expect(getLatestFaceCrop()).toBeNull();
  });
});

describe('TfliteEmbeddingExtractor', () => {
  it('runs the model on the normalized crop and L2-normalizes the 128-dim output', async () => {
    const raw = Array.from({ length: EMBEDDING_DIM }, (_, i) => (i % 7) - 3);
    const extractor = new TfliteEmbeddingExtractor(fakeModel(raw));
    const embedding = await extractor.extractEmbedding(syntheticCrop());
    expect(embedding).toHaveLength(EMBEDDING_DIM);
    const norm = Math.sqrt(embedding.reduce((s, v) => s + v * v, 0));
    expect(norm).toBeCloseTo(1, 5);
  });

  it('fails closed when the input is not a captured crop tensor', async () => {
    const extractor = new TfliteEmbeddingExtractor(fakeModel(Array(EMBEDDING_DIM).fill(0.1)));
    await expect(extractor.extractEmbedding('skeleton-frame')).rejects.toThrow();
    await expect(extractor.extractEmbedding(new Float32Array(42))).rejects.toThrow();
  });

  it('fails closed when the model output has the wrong dimension', async () => {
    const extractor = new TfliteEmbeddingExtractor(fakeModel([1, 2, 3]));
    await expect(extractor.extractEmbedding(syntheticCrop())).rejects.toThrow();
  });

  it('fails closed on a zero model output (l2Normalize refuses zero vectors)', async () => {
    const extractor = new TfliteEmbeddingExtractor(fakeModel(Array(EMBEDDING_DIM).fill(0)));
    await expect(extractor.extractEmbedding(syntheticCrop())).rejects.toThrow();
  });
});
