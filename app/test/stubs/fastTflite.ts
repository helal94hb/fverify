/**
 * Jest stand-in for react-native-fast-tflite (a native module — never loaded
 * in unit tests; mapped via jest.config.js moduleNameMapper).
 *
 * The stub makes model loading FAIL (the native runtime is absent), so the
 * app's extractor-resolution path deterministically falls back to the stub
 * extractor under jest. Pure helpers (crop math, preprocessing, L2
 * normalization) are tested directly with an injected fake model.
 */

import type { TensorflowModel, TensorflowPlugin } from 'react-native-fast-tflite';

export const loadTensorflowModel = (): Promise<TensorflowModel> =>
  Promise.reject(new Error('react-native-fast-tflite is not linked in jest'));

export const useTensorflowModel = (): TensorflowPlugin => ({
  state: 'error',
  model: undefined,
  error: new Error('react-native-fast-tflite is not linked in jest'),
});
