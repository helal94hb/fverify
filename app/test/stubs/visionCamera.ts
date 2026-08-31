/**
 * Jest stand-in for react-native-vision-camera (a native module — never
 * loaded in unit tests; mapped via jest.config.js moduleNameMapper).
 * The stub makes every camera lookup return "no device", so camera screens
 * deterministically render their guidance-placeholder path under jest.
 */

import type { ReactElement } from 'react';

export const Camera = (): ReactElement | null => null;

export const useCameraDevice = (_position: 'front' | 'back' | 'external'): undefined => undefined;

export const useCameraPermission = (): {
  hasPermission: boolean;
  requestPermission: () => Promise<boolean>;
} => ({
  hasPermission: false,
  requestPermission: () => Promise.resolve(false),
});
