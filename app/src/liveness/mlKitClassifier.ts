/**
 * PURE face-observation → liveness-signal classifier — no React, no native
 * imports, fully jest-testable.
 *
 * Input: one face observation per processed frame (from the ML Kit frame
 * processor — eye-open probabilities and head yaw). Output: at most one
 * LivenessSignal per frame, edge-triggered so a held pose does not emit a
 * stream of duplicate signals.
 *
 * Fail closed by construction: face-absent frames emit NOTHING and reset the
 * blink baseline — a hand over the camera never looks like a blink, and the
 * challenge engine only passes on an explicit matching signal.
 */

import type { LivenessSignal } from './engine';

/** One frame's face measurement, already extracted from the detector plugin. */
export interface FaceObservation {
  /** ML Kit leftEyeOpenProbability, 0 (closed) … 1 (open). */
  leftEyeOpenProbability: number;
  /** ML Kit rightEyeOpenProbability, 0 (closed) … 1 (open). */
  rightEyeOpenProbability: number;
  /** ML Kit headEulerAngleY in degrees (sign convention is camera-dependent). */
  yawAngle: number;
}

export interface FaceSignalClassifierOptions {
  /** Both eyes below this count as closed. ML Kit noise floor is ~0.1. */
  eyeClosedThreshold?: number;
  /** Both eyes above this (re-)arm the blink edge — blink = open → closed. */
  eyeOpenThreshold?: number;
  /** |yaw| past this counts as a completed head turn. */
  yawTriggerDegrees?: number;
  /** |yaw| back below this re-arms the turn edge (hysteresis). */
  yawResetDegrees?: number;
  /**
   * DEVICE-CALIBRATION CONSTANT: ML Kit reports headEulerAngleY relative to
   * the image being processed; whether a subject's physical left turn reads
   * positive or negative depends on the front camera's mirroring and the
   * frame orientation handed to ML Kit. Default +1 maps positive yaw to
   * 'turn-left'; flip to -1 if on-device testing shows the convention
   * reversed. (A wrong sign here fails the challenge — never a false pass.)
   */
  yawSign?: 1 | -1;
}

const DEFAULT_EYE_CLOSED = 0.2;
const DEFAULT_EYE_OPEN = 0.8;
const DEFAULT_YAW_TRIGGER = 30;
const DEFAULT_YAW_RESET = 15;

export class FaceSignalClassifier {
  private readonly eyeClosedThreshold: number;
  private readonly eyeOpenThreshold: number;
  private readonly yawTriggerDegrees: number;
  private readonly yawResetDegrees: number;
  private readonly yawSign: 1 | -1;

  /** Blink edge state: a blink counts only when eyes were seen OPEN first. */
  private eyesWereOpen = false;
  /** Turn edge state: the excursion currently in progress, if any. */
  private activeTurn: 'turn-left' | 'turn-right' | null = null;

  constructor(options: FaceSignalClassifierOptions = {}) {
    this.eyeClosedThreshold = options.eyeClosedThreshold ?? DEFAULT_EYE_CLOSED;
    this.eyeOpenThreshold = options.eyeOpenThreshold ?? DEFAULT_EYE_OPEN;
    this.yawTriggerDegrees = options.yawTriggerDegrees ?? DEFAULT_YAW_TRIGGER;
    this.yawResetDegrees = options.yawResetDegrees ?? DEFAULT_YAW_RESET;
    this.yawSign = options.yawSign ?? 1;
  }

  /** Forget all edge state (new run, face lost, detector stopped). */
  reset(): void {
    this.eyesWereOpen = false;
    this.activeTurn = null;
  }

  /**
   * Classify one frame. Returns the signal to emit, or null.
   * A blink edge wins over a turn when both complete in the same frame —
   * eye closure is the less ambiguous measurement.
   */
  classify(face: FaceObservation | null): LivenessSignal | null {
    if (!face) {
      // Face-absent: emit nothing, and re-arm the blink baseline so covering
      // the camera between frames cannot manufacture an open→closed edge.
      this.reset();
      return null;
    }

    const blink = this.classifyBlink(face);
    if (blink) return blink;
    return this.classifyTurn(face);
  }

  private classifyBlink(face: FaceObservation): 'blink' | null {
    const left = face.leftEyeOpenProbability;
    const right = face.rightEyeOpenProbability;
    if (left < this.eyeClosedThreshold && right < this.eyeClosedThreshold) {
      const completed = this.eyesWereOpen;
      this.eyesWereOpen = false;
      return completed ? 'blink' : null;
    }
    if (left > this.eyeOpenThreshold && right > this.eyeOpenThreshold) {
      this.eyesWereOpen = true;
    }
    return null;
  }

  private classifyTurn(face: FaceObservation): 'turn-left' | 'turn-right' | null {
    const yaw = face.yawAngle * this.yawSign;
    if (this.activeTurn && Math.abs(yaw) < this.yawResetDegrees) {
      // Head returned to neutral — re-arm for the next excursion.
      this.activeTurn = null;
    }
    if (this.activeTurn) return null;
    if (yaw > this.yawTriggerDegrees) {
      this.activeTurn = 'turn-left';
      return 'turn-left';
    }
    if (yaw < -this.yawTriggerDegrees) {
      this.activeTurn = 'turn-right';
      return 'turn-right';
    }
    return null;
  }
}
