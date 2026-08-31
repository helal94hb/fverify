/**
 * Jest stand-in for react-native-worklets-core (a native module — never
 * loaded in unit tests; mapped via jest.config.js moduleNameMapper).
 *
 * In the real runtime, `useRunOnJS` builds the memoized worklet that hops
 * from the frame-processor thread back to the JS thread. In jest, frame
 * processors never execute (the camera stub renders no device), so a
 * synchronous passthrough of the callback is the honest no-op.
 */

export const useRunOnJS = <T extends (...args: never[]) => unknown>(callback: T): T => callback;

/** Shared-value stand-in: a plain mutable box (single-threaded under jest). */
export const useSharedValue = <T>(initial: T): { value: T } => ({ value: initial });

/** Minimal Worklets context placeholder — never exercised in tests. */
export const Worklets = {
  createRunInContextFn: <T extends (...args: never[]) => unknown>(fn: T): T => fn,
};
