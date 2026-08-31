/**
 * Document capture — camera SHELL with framing guidance (national ID
 * front/back, design §3 step 2). The capture stays on-device; the image is
 * discarded after the flow and never uploaded (design §4).
 *
 * VISION-CAMERA WIRING: renders the real <Camera> (front camera, consistent
 * with the selfie-first flow of this app) when a device and permission exist;
 * jest maps vision-camera to a stub that reports no device, so unit tests
 * deterministically render the guidance-placeholder path.
 *
 * Document edge detection/auto-capture is explicitly a NEXT-iteration item
 * (a document model is not part of this pipeline), so this screen attaches no
 * frame processor yet — the camera is preview-only here.
 */

import React, { useEffect } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { Camera, useCameraDevice, useCameraPermission } from 'react-native-vision-camera';

export interface DocumentCaptureScreenProps {
  onCaptured: () => void;
}

export function DocumentCaptureScreen({
  onCaptured,
}: DocumentCaptureScreenProps): React.JSX.Element {
  const device = useCameraDevice('front');
  const { hasPermission, requestPermission } = useCameraPermission();

  useEffect(() => {
    if (!hasPermission) void requestPermission();
  }, []);

  return (
    <View style={styles.container} testID="document-capture-screen">
      <Text style={styles.title}>Scan your national ID</Text>
      <View style={styles.cameraShell} testID="document-camera-shell">
        {device && hasPermission ? (
          // Native path — exercised only on a real device, never in jest.
          <Camera style={StyleSheet.absoluteFill} device={device} isActive />
        ) : (
          // Emulator/test path: framing guidance placeholder.
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
