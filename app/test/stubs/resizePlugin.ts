/**
 * Jest stand-in for vision-camera-resize-plugin (a native frame-processor
 * plugin — never loaded in unit tests; mapped via jest.config.js
 * moduleNameMapper). Frame processors never execute under jest, so the
 * resize function is an inert placeholder.
 */

import type { ResizePlugin } from 'vision-camera-resize-plugin';

export const useResizePlugin = (): ResizePlugin => ({
  resize: () => {
    throw new Error('vision-camera-resize-plugin is not linked in jest');
  },
});

export const createResizePlugin = useResizePlugin;
