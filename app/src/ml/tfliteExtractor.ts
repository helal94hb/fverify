/**
 * REAL on-device embedding extractor — MobileFaceNet via react-native-fast-tflite.
 *
 * Pipeline (design doc §2, wiring point documented in ./embedding.ts):
 *   1. The liveness screen's vision-camera frame processor (worklet) detects
 *      the face (ML Kit), crops the face region, and resizes it to
 *      112×112 RGB float32 via vision-camera-resize-plugin.
 *   2. A worklet cannot call async JS — the cropped tensor crosses the
 *      frame-processor→JS boundary through `runOnJS` into the mailbox below
 *      (`captureFaceCrop`). Face IMAGES never leave the phone and are never
 *      stored; the crop tensor lives only in memory until the embedding is
 *      extracted, then is dropped (design §4).
 *   3. The processing step feeds the captured crop to this extractor, which
 *      normalizes the pixels, runs the model, L2-normalizes the 128-dim
 *      output (`l2Normalize` — the backend's cosine match assumes unit
 *      vectors), and returns it for sealing.
 *
 * Model: assets/models/mobilefacenet.tflite (MobileFaceNet-class,
 * Apache-2.0). Input 112×112 RGB float32, output 128-dim embedding.
 */

import { loadTensorflowModel, type TensorflowModel } from 'react-native-fast-tflite';
import {
  EMBEDDING_DIM,
  l2Normalize,
  type CameraFrame,
  type EmbeddingExtractor,
} from './embedding';
import mobilefacenetModel from '../../assets/models/mobilefacenet.tflite';

/** MobileFaceNet input geometry: 112×112 RGB, 3 channels. */
export const FACE_CROP_SIZE = 112;
export const FACE_CROP_CHANNELS = 3;
export const FACE_CROP_LENGTH = FACE_CROP_SIZE * FACE_CROP_SIZE * FACE_CROP_CHANNELS;

/**
 * How raw [0..1] pixels are mapped into model input range. MobileFaceNet-class
 * models are trained on (pixel - 0.5) / 0.5, i.e. [-1, 1]; 'signed' is the
 * default. Kept explicit (and injectable in tests) because feeding the wrong
 * range silently degrades match accuracy instead of failing.
 */
export type PixelNormalization = 'signed' | 'zero-one';

// -- face-crop mailbox (the runOnJS bridge landing zone) ------------------------

let latestFaceCrop: Float32Array | null = null;

/**
 * Called on the JS thread from the frame processor via runOnJS with the
 * latest 112×112 RGB float32 face crop. Overwrites any previous crop — only
 * the freshest face matters for the embedding that follows a passed liveness
 * run. The tensor is held only in memory and is cleared when a new liveness
 * run starts (clearFaceCrop) — never persisted, never uploaded.
 */
export function captureFaceCrop(crop: Float32Array): void {
  latestFaceCrop = crop;
}

/** The freshest captured face crop, or null when no face has been captured. */
export function getLatestFaceCrop(): Float32Array | null {
  return latestFaceCrop;
}

/** Drop the captured crop (new liveness run, or after extraction). */
export function clearFaceCrop(): void {
  latestFaceCrop = null;
}

// -- pure helpers (unit-tested) ---------------------------------------------------

export interface FaceBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface CropRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * Face bounding box → square crop rect in FRAME coordinates, expanded by
 * `marginRatio` on each side (face embeddings expect some surrounding
 * context, not a tight skin-tight box) and clamped to the frame.
 *
 * Orientation caveat: ML Kit bounds are in the upright-image coordinate space
 * the detector processed; the resize plugin crops in raw frame space. For the
 * front camera in portrait these coincide only when the frame processor
 * accounts for frame.orientation — that mapping is an on-device calibration
 * step (Phase B benchmark), noted here rather than silently assumed.
 */
export function computeFaceCropRect(
  bounds: FaceBounds,
  frameWidth: number,
  frameHeight: number,
  marginRatio = 0.25,
): CropRect {
  const side = Math.max(bounds.width, bounds.height) * (1 + marginRatio * 2);
  const centerX = bounds.x + bounds.width / 2;
  const centerY = bounds.y + bounds.height / 2;
  const x = Math.max(0, Math.min(frameWidth - side, centerX - side / 2));
  const y = Math.max(0, Math.min(frameHeight - side, centerY - side / 2));
  const clampedSide = Math.min(side, frameWidth, frameHeight);
  return { x: Math.round(x), y: Math.round(y), width: Math.round(clampedSide), height: Math.round(clampedSide) };
}

/**
 * Map [0..1] float32 RGB pixels into the model's expected input range.
 * Returns a NEW array — the input buffer belongs to the resize plugin.
 */
export function normalizeFaceCrop(
  crop: Float32Array,
  normalization: PixelNormalization = 'signed',
): Float32Array {
  if (crop.length !== FACE_CROP_LENGTH) {
    // Fail closed: a malformed tensor must never reach the model.
    throw new Error(`face crop must have ${FACE_CROP_LENGTH} values, got ${crop.length}`);
  }
  if (normalization === 'zero-one') return new Float32Array(crop);
  const out = new Float32Array(crop.length);
  for (let i = 0; i < crop.length; i++) {
    out[i] = crop[i]! * 2 - 1;
  }
  return out;
}

// -- the real extractor ---------------------------------------------------------------

export interface TfliteEmbeddingExtractorOptions {
  pixelNormalization?: PixelNormalization;
}

/**
 * Runs mobilefacenet.tflite on a captured 112×112 face crop and returns the
 * L2-normalized 128-dim embedding. Instances come from `load()` — the model
 * file is bundled with the app (no download; the app works fully on-device).
 */
export class TfliteEmbeddingExtractor implements EmbeddingExtractor {
  private readonly model: TensorflowModel;
  private readonly pixelNormalization: PixelNormalization;

  constructor(model: TensorflowModel, options: TfliteEmbeddingExtractorOptions = {}) {
    this.model = model;
    this.pixelNormalization = options.pixelNormalization ?? 'signed';
  }

  /** Load the bundled model. Rejects when the native runtime/model is absent. */
  static async load(options?: TfliteEmbeddingExtractorOptions): Promise<TfliteEmbeddingExtractor> {
    const model = await loadTensorflowModel(mobilefacenetModel);
    return new TfliteEmbeddingExtractor(model, options);
  }

  /**
   * `input` must be the 112×112×3 float32 crop produced by the frame
   * processor (see the mailbox above) — the opaque CameraFrame handle from
   * the skeleton contract is realized as that tensor. Anything else fails
   * closed (a non-face input must never produce an embedding).
   */
  async extractEmbedding(input: CameraFrame): Promise<number[]> {
    if (!(input instanceof Float32Array) || input.length !== FACE_CROP_LENGTH) {
      throw new Error('extractEmbedding requires a captured 112x112 face crop tensor');
    }
    const [output] = await this.model.run([normalizeFaceCrop(input, this.pixelNormalization)]);
    if (!output || output.length !== EMBEDDING_DIM) {
      throw new Error(`model output must have ${EMBEDDING_DIM} dimensions`);
    }
    return l2Normalize(Array.from(output as Float32Array));
  }
}
