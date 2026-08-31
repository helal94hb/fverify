/**
 * Document capture — camera SHELL with framing guidance (national ID
 * front/back, design §3 step 2). The capture stays on-device; the image is
 * discarded after the flow and never uploaded (design §4).
 *
 * VISION-CAMERA WIRING POINT (this pass = shell only, no frame processing):
 *   - The real capture uses <Camera> from react-native-vision-camera with the
 *     back device; jest maps that module to a pure-JS stub, so this screen
 *     renders its guidance path in unit tests.
 *   - Next iteration adds a frame processor that detects the document edges
 *     on-device and auto-captures when the framing is good; the captured
 *     frame feeds the document checks, then is discarded.
 */

import React from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { Camera, useCameraDevice } from 'react-native-vision-camera';

export interface DocumentCaptureScreenProps {
  onCaptured: () => void;
}

export function DocumentCaptureScreen({
  onCaptured,
}: DocumentCaptureScreenProps): React.JSX.Element {
  const device = useCameraDevice('back');

  return (
    <View style={styles.container} testID="document-capture-screen">
      <Text style={styles.title}>Scan your national ID</Text>
      <View style={styles.cameraShell} testID="document-camera-shell">
        {device ? (
          // Native path — exercised only on a real device, never in jest.
          <Camera style={StyleSheet.absoluteFill} device={device} isActive />
        ) : (
          // Skeleton/test path: framing guidance placeholder.
          <View style={styles.framingGuide} testID="document-framing-guide">
            <Text style={styles.framingText}>
              Camera preview appears here.{'\n\n'}Place the front of your national ID inside the
              frame, in good light, flat and without glare.
            </Text>
          </View>
        )}
        <View style={styles.frameCorners} pointerEvents="none" />
      </View>
      <Text style={styles.hint}>Front side first — the back side is captured next.</Text>
      <Pressable
        style={styles.primaryButton}
        testID="document-capture-button"
        onPress={onCaptured}
      >
        <Text style={styles.primaryButtonText}>Capture</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24 },
  title: { fontSize: 22, fontWeight: '700', marginBottom: 16, textAlign: 'center' },
  cameraShell: {
    flex: 1,
    borderRadius: 12,
    overflow: 'hidden',
    backgroundColor: '#111111',
    justifyContent: 'center',
  },
  framingGuide: { alignItems: 'center', padding: 24 },
  framingText: { color: '#e0e0e0', fontSize: 15, lineHeight: 22, textAlign: 'center' },
  frameCorners: {
    position: 'absolute',
    top: 24,
    bottom: 24,
    start: 24,
    end: 24,
    borderWidth: 2,
    borderColor: '#81c784',
    borderRadius: 8,
  },
  hint: { fontSize: 13, opacity: 0.7, textAlign: 'center', marginVertical: 16 },
  primaryButton: {
    backgroundColor: '#1b5e20',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  primaryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
});
