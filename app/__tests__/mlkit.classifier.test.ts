/**
 * Face-signal classifier — the PURE core of the ML Kit liveness detector.
 * Blink edge detection, turn hysteresis, face-absent fail-closed, and the
 * detector's start/stop gating. No native modules, no PII — synthetic
 * observations only.
 */

import {
  FaceSignalClassifier,
  type FaceObservation,
} from '../src/liveness/mlKitClassifier';
import { MlKitLivenessSignalDetector } from '../src/liveness/mlKitDetector';
import type { LivenessSignal } from '../src/liveness/engine';

const openEyes: Pick<FaceObservation, 'leftEyeOpenProbability' | 'rightEyeOpenProbability'> = {
  leftEyeOpenProbability: 0.95,
  rightEyeOpenProbability: 0.95,
};

const closedEyes: Pick<FaceObservation, 'leftEyeOpenProbability' | 'rightEyeOpenProbability'> = {
  leftEyeOpenProbability: 0.05,
  rightEyeOpenProbability: 0.05,
};

function face(partial: Partial<FaceObservation>): FaceObservation {
  return { ...openEyes, yawAngle: 0, ...partial };
}

describe('FaceSignalClassifier — blink', () => {
  it('emits blink on an open → closed edge', () => {
    const c = new FaceSignalClassifier();
    expect(c.classify(face({}))).toBeNull(); // baseline: eyes open
    expect(c.classify(face(closedEyes))).toBe('blink');
  });

  it('does not emit when eyes start closed (no open baseline observed)', () => {
    const c = new FaceSignalClassifier();
    expect(c.classify(face(closedEyes))).toBeNull();
  });

  it('emits once per blink — a held closed state does not repeat', () => {
    const c = new FaceSignalClassifier();
    c.classify(face({}));
    expect(c.classify(face(closedEyes))).toBe('blink');
    expect(c.classify(face(closedEyes))).toBeNull();
    expect(c.classify(face(closedEyes))).toBeNull();
  });

  it('re-arms only after eyes open again — a second blink is a second signal', () => {
    const c = new FaceSignalClassifier();
    c.classify(face({}));
    expect(c.classify(face(closedEyes))).toBe('blink');
    c.classify(face({}));
    expect(c.classify(face(closedEyes))).toBe('blink');
  });

  it('one closed eye is never a blink', () => {
    const c = new FaceSignalClassifier();
    c.classify(face({}));
    expect(
      c.classify(face({ leftEyeOpenProbability: 0.05, rightEyeOpenProbability: 0.9 })),
    ).toBeNull();
  });
});

describe('FaceSignalClassifier — head turns', () => {
  it('emits turn-left past +30 deg and turn-right past -30 deg', () => {
    const c = new FaceSignalClassifier();
    expect(c.classify(face({ yawAngle: 35 }))).toBe('turn-left');
    const c2 = new FaceSignalClassifier();
    expect(c2.classify(face({ yawAngle: -35 }))).toBe('turn-right');
  });

  it('emits nothing below the threshold', () => {
    const c = new FaceSignalClassifier();
    expect(c.classify(face({ yawAngle: 29 }))).toBeNull();
    expect(c.classify(face({ yawAngle: -29 }))).toBeNull();
  });

  it('hysteresis: holds the excursion until the head returns below the reset band', () => {
    const c = new FaceSignalClassifier();
    expect(c.classify(face({ yawAngle: 40 }))).toBe('turn-left');
    expect(c.classify(face({ yawAngle: 45 }))).toBeNull(); // still in excursion
    expect(c.classify(face({ yawAngle: 20 }))).toBeNull(); // between bands: not re-armed
    expect(c.classify(face({ yawAngle: 10 }))).toBeNull(); // back to neutral: re-armed
    expect(c.classify(face({ yawAngle: 40 }))).toBe('turn-left'); // a NEW excursion
  });

  it('yawSign flips the mapping (device-calibration constant)', () => {
    const c = new FaceSignalClassifier({ yawSign: -1 });
    expect(c.classify(face({ yawAngle: 35 }))).toBe('turn-right');
  });
});

describe('FaceSignalClassifier — fail closed', () => {
  it('face-absent frames emit nothing', () => {
    const c = new FaceSignalClassifier();
    expect(c.classify(null)).toBeNull();
  });

  it('face-absent resets the blink baseline — covering the camera cannot manufacture a blink', () => {
    const c = new FaceSignalClassifier();
    c.classify(face({})); // eyes open
    c.classify(null); // face lost
    expect(c.classify(face(closedEyes))).toBeNull(); // closed WITHOUT a fresh open baseline
  });

  it('reset() forgets edge state', () => {
    const c = new FaceSignalClassifier();
    c.classify(face({}));
    c.reset();
    expect(c.classify(face(closedEyes))).toBeNull();
  });
});

describe('MlKitLivenessSignalDetector — engine-facing gating', () => {
  it('emits only while started; stop() silences it', () => {
    const detector = new MlKitLivenessSignalDetector();
    const signals: LivenessSignal[] = [];
    detector.handleFaces([face(closedEyes)]); // not started: dropped
    detector.start((s) => signals.push(s));
    detector.handleFaces([face({})]);
    detector.handleFaces([face(closedEyes)]);
    detector.stop();
    detector.handleFaces([face({})]);
    detector.handleFaces([face(closedEyes)]); // after stop: dropped
    expect(signals).toEqual(['blink']);
  });

  it('face-absent observation arrays emit nothing', () => {
    const detector = new MlKitLivenessSignalDetector();
    const signals: LivenessSignal[] = [];
    detector.start((s) => signals.push(s));
    detector.handleFaces([]);
    expect(signals).toEqual([]);
  });
});
