/**
 * Jest stand-in for *.tflite asset imports (the binary model file is never
 * parsed by the test runner; mapped via jest.config.js moduleNameMapper).
 */

const stubAsset = 0;
export default stubAsset;
