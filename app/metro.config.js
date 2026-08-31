/**
 * Metro config — standalone app (no workspace hoisting concerns here).
 * The `tflite` asset extension lets `require('./assets/models/mobilefacenet.tflite')`
 * bundle the on-device embedding model (react-native-fast-tflite loads it from
 * the bundle; the model ships inside the app, never downloaded).
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

const defaultConfig = getDefaultConfig(__dirname);

module.exports = mergeConfig(defaultConfig, {
  resolver: {
    assetExts: [...defaultConfig.resolver.assetExts, 'tflite'],
  },
});
