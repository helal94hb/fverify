/**
 * Jest stand-in for react-native-vision-camera-face-detector (a native
 * frame-processor plugin wrapping ML Kit — never loaded in unit tests;
 * mapped via jest.config.js moduleNameMapper).
 *
 * The stub detector sees NO faces: detection runs only inside a real frame
 * processor on a device, and jest never executes one. An empty result is the
 * fail-closed default (face-absent emits nothing).
 */

export interface StubFace {
  pitchAngle: number;
  rollAngle: number;
  yawAngle: number;
  bounds: { width: number; height: number; x: number; y: number };
  leftEyeOpenProbability: number;
  rightEyeOpenProbability: number;
  smilingProbability: number;
}

export interface StubFaceDetectorPlugin {
  detectFaces: (frame: unknown) => StubFace[];
  stopListeners: () => void;
}

export const useFaceDetector = (): StubFaceDetectorPlugin => ({
  detectFaces: () => [],
  stopListeners: () => undefined,
});
