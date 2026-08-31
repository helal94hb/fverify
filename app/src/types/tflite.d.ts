/**
 * Metro bundles `.tflite` files as registered asset modules (see
 * metro.config.js assetExts) — the import resolves to the asset reference
 * react-native-fast-tflite's `loadTensorflowModel` expects.
 * Jest maps this pattern to a stub (jest.config.js moduleNameMapper) — the
 * real model file is never parsed by the test runner.
 */
declare module '*.tflite' {
  const asset: number;
  export default asset;
}
