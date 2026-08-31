module.exports = {
  preset: 'react-native',
  // Native modules are never loaded in unit tests. Any native import we add
  // (vision-camera today; the TFLite frame processor next iteration) MUST get
  // a pure-JS stand-in here so jest stays hermetic and never touches a build.
  moduleNameMapper: {
    '^react-native-vision-camera$': '<rootDir>/test/stubs/visionCamera.ts',
  },
};
