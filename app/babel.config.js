module.exports = {
  presets: ['module:@react-native/babel-preset'],
  plugins: [
    // vision-camera frame processors are worklets — the worklets-core babel
    // plugin compiles the 'worklet' directives for the vision-camera frame
    // processor runtime (required by react-native-vision-camera v4).
    'react-native-worklets-core/plugin',
  ],
};
