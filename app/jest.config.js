module.exports = {
  preset: 'react-native',
  // Native modules are never loaded in unit tests. Every native import
  // (vision-camera, worklets-core, fast-tflite, the resize plugin, and the
  // ML Kit face-detector plugin) MUST get a pure-JS stand-in here so jest
  // stays hermetic and never touches a build.
  moduleNameMapper: {
    '^react-native-vision-camera$': '<rootDir>/test/stubs/visionCamera.ts',
    '^react-native-worklets-core$': '<rootDir>/test/stubs/workletsCore.ts',
    '^react-native-fast-tflite$': '<rootDir>/test/stubs/fastTflite.ts',
    '^vision-camera-resize-plugin$': '<rootDir>/test/stubs/resizePlugin.ts',
    '^react-native-vision-camera-face-detector$': '<rootDir>/test/stubs/faceDetectorPlugin.ts',
    '\\.tflite$': '<rootDir>/test/stubs/tfliteAsset.ts',
  },
};
