/**
 * REAL liveness signal detector — vision-camera frame processor → ML Kit face
 * detection → the pure FaceSignalClassifier → engine signals.
 *
 * FACE-DETECTION PACKAGE DECISION (documented, deliberate): the brief's first
 * candidate, `@infinitered/react-native-mlkit-face-detection`, was evaluated
 * and REJECTED for this pipeline: its API is photo-URI based
 * (`detectFaces(imageUri)`), it drags the entire `expo` package into this
 * bare RN app, and photo polling cannot catch a 100–400 ms blink inside a
 * challenge window. The other published options (`@react-native-ml-kit/*`,
 * the 2022 `vision-camera-face-detector`) are either photo-based too or built
 * for the vision-camera v2 ABI. The best-current equivalent compatible with
 * the mandated vision-camera v4 + worklets-core stack is
 * `react-native-vision-camera-face-detector` (1.x line — its 2.x moved to the
 * vision-camera v5/Nitro ABI): a frame-processor plugin wrapping Google's
 * `com.google.mlkit:face-detection` SDK, exposing per-frame eye-open
 * probabilities, head yaw, and bounds inside the worklet.
 *
 * Signal policy (all in the PURE classifier, jest-tested): blink = both
 * eye-open probabilities below 0.2 after an observed open baseline; turns =
 * |yaw| past 30° with 15° re-arm hysteresis; face-absent emits NOTHING (fail
 * closed — no signal, no pass).
 */

import { useEffect, useMemo } from 'react';
import {
  useFrameProcessor,
  type ReadonlyFrameProcessor,
} from 'react-native-vision-camera';
import { useRunOnJS, useSharedValue } from 'react-native-worklets-core';
import { useFaceDetector } from 'react-native-vision-camera-face-detector';
import { useResizePlugin } from 'vision-camera-resize-plugin';
import type { LivenessSignal, SignalDetector } from './engine';
import {
  FaceSignalClassifier,
  type FaceObservation,
  type FaceSignalClassifierOptions,
} from './mlKitClassifier';
import {
  captureFaceCrop,
  computeFaceCropRect,
  FACE_CROP_SIZE,
} from '../ml/tfliteExtractor';

/**
 * The detector the engine drives. Owns no camera itself — the screen renders
 * the Camera and routes frame-processor observations in through
 * `handleFaces` (via runOnJS). start/stop only gate whether observations may
 * become signals, and reset the classifier edge state between runs.
 */
export class MlKitLivenessSignalDetector implements SignalDetector {
  private emit: ((signal: LivenessSignal) => void) | null = null;
  private readonly classifier: FaceSignalClassifier;

  constructor(options?: FaceSignalClassifierOptions) {
    this.classifier = new FaceSignalClassifier(options);
  }

  start(emit: (signal: LivenessSignal) => void): void {
    this.classifier.reset();
    this.emit = emit;
  }

  stop(): void {
    this.emit = null;
    this.classifier.reset();
  }

  /**
   * JS-thread entry point for frame-processor observations. Face-absent
   * frames (empty array) are forwarded as null — the classifier emits
   * nothing for them. When the engine is not listening, everything drops.
   */
  handleFaces(faces: FaceObservation[]): void {
    const emit = this.emit;
    if (!emit) return;
    const signal = this.classifier.classify(faces[0] ?? null);
    if (signal) emit(signal);
  }
}

/** Minimum milliseconds between processed frames (ML Kit fast mode budget). */
const FRAME_INTERVAL_MS = 150;

/**
 * The frame processor that feeds a MlKitLivenessSignalDetector AND captures
 * the freshest face crop into the embedding mailbox (the runOnJS bridge from
 * the documented wiring point in ml/embedding.ts). One worklet does both —
 * vision-camera runs a single frame processor per Camera.
 */
export function useMlKitLivenessFrameProcessor(
  detector: MlKitLivenessSignalDetector,
): ReadonlyFrameProcessor {
  const faceDetector = useFaceDetector({
    performanceMode: 'fast',
    classificationMode: 'all', // required for eye-open probabilities
    landmarkMode: 'none',
    contourMode: 'none',
    minFaceSize: 0.15,
    cameraFacing: 'front',
  });
  const { resize } = useResizePlugin();
  // Worklet-side throttle state — a worklets-core shared value survives
  // across frames on the worklet thread (a plain ref does not).
  const lastProcessedAtMs = useSharedValue(0);

  // Release the plugin's Android orientation listener with the screen.
  useEffect(() => () => faceDetector.stopListeners(), [faceDetector]);

  // JS-thread bridge as a memoized runOnJS worklet: observations become
  // signals, the crop tensor lands in the mailbox. (worklets-core 1.x has no
  // top-level runOnJS export — useRunOnJS is the frame-processor hop API.)
  const bridge = useRunOnJS(
    (faces: FaceObservation[], crop: Float32Array | null) => {
      detector.handleFaces(faces);
      if (crop && crop.length > 0) captureFaceCrop(crop);
    },
    [detector],
  );

  return useFrameProcessor(
    (frame) => {
      'worklet';
      // Throttle: frame.timestamp is the host clock in nanoseconds.
      const nowMs = frame.timestamp / 1e6;
      if (nowMs - lastProcessedAtMs.value < FRAME_INTERVAL_MS) return;
      lastProcessedAtMs.value = nowMs;

      const faces = faceDetector.detectFaces(frame);
      const observations: FaceObservation[] = faces.map((f) => ({
        leftEyeOpenProbability: f.leftEyeOpenProbability,
        rightEyeOpenProbability: f.rightEyeOpenProbability,
        yawAngle: f.yawAngle,
      }));

      // Crop the most prominent face to the 112x112 RGB float32 model input.
      // Bounds are in the detector's image space; see the orientation caveat
      // on computeFaceCropRect.
      let crop: Float32Array | null = null;
      const first = faces[0];
      if (first) {
        const rect = computeFaceCropRect(first.bounds, frame.width, frame.height);
        crop = resize(frame, {
          crop: rect,
          scale: { width: FACE_CROP_SIZE, height: FACE_CROP_SIZE },
          pixelFormat: 'rgb',
          dataType: 'float32',
        });
      }

      bridge(observations, crop);
    },
    [faceDetector, resize, bridge],
  );
}

/** Convenience: one detector instance per mounted screen. */
export function useMlKitLivenessDetector(
  options?: FaceSignalClassifierOptions,
): MlKitLivenessSignalDetector {
  return useMemo(() => new MlKitLivenessSignalDetector(options), []);
}
