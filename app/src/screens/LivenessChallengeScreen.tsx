/**
 * Guided liveness — the randomized challenge loop UI (design §3/§5).
 *
 * One challenge at a time (blink / turn-left / turn-right), each with its own
 * time window, progress visible throughout. All logic lives in the PURE
 * engine (../liveness/engine.ts); this screen only renders engine snapshots
 * and forwards the designed retry.
 *
 * DETECTOR WIRING (real): the default detector is the ML Kit one — the front
 * camera runs a vision-camera frame processor whose face observations (eye-
 * open probabilities, head yaw) become engine signals via the pure
 * classifier, and whose freshest 112x112 face crop lands in the embedding
 * mailbox for the processing step. When no camera device exists (emulator,
 * jest) the screen renders its guidance placeholder and the engine simply
 * times out — fail closed, never a pass.
 */

import React, { useEffect, useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { Camera, useCameraDevice, useCameraPermission } from 'react-native-vision-camera';
import {
  LivenessEngine,
  LivenessSnapshot,
  type Challenge,
  type SignalDetector,
} from '../liveness/engine';
import {
  useMlKitLivenessDetector,
  useMlKitLivenessFrameProcessor,
} from '../liveness/mlKitDetector';
import { clearFaceCrop } from '../ml/tfliteExtractor';

const CHALLENGE_COPY: Record<Challenge, string> = {
  blink: 'Blink your eyes',
  'turn-left': 'Slowly turn your head to the left',
  'turn-right': 'Slowly turn your head to the right',
};

/**
 * TEST SEAM: a SignalDetector that observes nothing. Jest and headless
 * harnesses inject this; production leaves the prop unset and gets the real
 * ML Kit detector. Clearly a stub — never the default on a device.
 */
export const stubSignalDetector: SignalDetector = {
  start: () => undefined,
  stop: () => undefined,
};

export interface LivenessChallengeScreenProps {
  detector?: SignalDetector;
  perChallengeTimeoutMs?: number;
  onPassed: () => void;
  onExhausted: () => void;
}

export function LivenessChallengeScreen({
  detector,
  perChallengeTimeoutMs,
  onPassed,
  onExhausted,
}: LivenessChallengeScreenProps): React.JSX.Element {
  const [snapshot, setSnapshot] = useState<LivenessSnapshot | null>(null);
  const engineRef = useRef<LivenessEngine | null>(null);

  // Real pipeline: front camera + ML Kit frame processor. In jest these are
  // stubs — no device, inert frame processor — so the placeholder path below
  // is what unit tests render.
  const device = useCameraDevice('front');
  const { hasPermission, requestPermission } = useCameraPermission();
  const mlKitDetector = useMlKitLivenessDetector();
  const frameProcessor = useMlKitLivenessFrameProcessor(mlKitDetector);
  const effectiveDetector = detector ?? mlKitDetector;

  useEffect(() => {
    if (!hasPermission) void requestPermission();
  }, []);

  useEffect(() => {
    // A fresh run starts with an empty face-crop mailbox — the embedding that
    // follows must come from THIS run's frames, never a stale capture.
    clearFaceCrop();
    const engine = new LivenessEngine({
      detector: effectiveDetector,
      ...(perChallengeTimeoutMs !== undefined ? { perChallengeTimeoutMs } : {}),
      onEvent: (event) => {
        setSnapshot(engine.getSnapshot());
        if (event.type === 'run-passed') onPassed();
        if (event.type === 'exhausted') onExhausted();
      },
    });
    engineRef.current = engine;
    engine.start();
    setSnapshot(engine.getSnapshot());
    return () => engine.dispose();
    // One engine per mount — a rerun remounts this screen via the flow machine.
  }, []);

  const cameraActive = device != null && hasPermission;

  if (!snapshot || snapshot.state === 'idle') {
    return <View style={styles.container} testID="liveness-screen" />;
  }

  if (snapshot.state === 'timeout') {
    return (
      <View style={styles.container} testID="liveness-screen">
        <Text style={styles.title}>We didn't catch that</Text>
        <Text style={styles.body}>
          The challenge timed out. Attempt {snapshot.attempt} of {snapshot.maxAttempts}.
        </Text>
        <Pressable
          style={styles.primaryButton}
          testID="liveness-retry-button"
          onPress={() => engineRef.current?.retry()}
        >
          <Text style={styles.primaryButtonText}>Try again</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <View style={styles.container} testID="liveness-screen">
      <Text style={styles.title}>Prove you're here</Text>
      <Text style={styles.progress} testID="liveness-progress">
        Step {Math.min(snapshot.passedCount + 1, snapshot.total)} of {snapshot.total}
      </Text>
      <View style={styles.cameraShell} testID="liveness-camera-shell">
        {cameraActive ? (
          // Native path — exercised only on a real device, never in jest.
          <Camera
            style={StyleSheet.absoluteFill}
            device={device}
            isActive
            frameProcessor={frameProcessor}
          />
        ) : (
          // Emulator/test path: no camera — the challenge will time out
          // (fail closed; the stub detector never passes anyone).
          <View style={styles.cameraPlaceholder}>
            <Text style={styles.cameraPlaceholderText}>
              Camera preview appears here.{'\n\n'}Center your face in the circle and follow the
              challenge below.
            </Text>
          </View>
        )}
      </View>
      <View style={styles.challengeCard}>
        <Text style={styles.challengeText} testID="liveness-challenge">
          {snapshot.currentChallenge ? CHALLENGE_COPY[snapshot.currentChallenge] : ''}
        </Text>
      </View>
      <View style={styles.dots} testID="liveness-dots">
        {snapshot.order.map((challenge, i) => (
          <View
            key={challenge}
            style={[styles.dot, i < snapshot.passedCount && styles.dotPassed]}
          />
        ))}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, justifyContent: 'center' },
  title: { fontSize: 22, fontWeight: '700', textAlign: 'center', marginBottom: 8 },
  progress: { fontSize: 14, opacity: 0.7, textAlign: 'center', marginBottom: 16 },
  body: { fontSize: 15, lineHeight: 22, textAlign: 'center', marginBottom: 24 },
  cameraShell: {
    height: 240,
    borderRadius: 12,
    overflow: 'hidden',
    backgroundColor: '#111111',
    justifyContent: 'center',
    marginBottom: 16,
  },
  cameraPlaceholder: { alignItems: 'center', padding: 24 },
  cameraPlaceholderText: { color: '#e0e0e0', fontSize: 14, lineHeight: 20, textAlign: 'center' },
  challengeCard: {
    borderWidth: 1,
    borderColor: '#9e9e9e',
    borderRadius: 12,
    padding: 32,
    alignItems: 'center',
  },
  challengeText: { fontSize: 20, fontWeight: '600', textAlign: 'center' },
  dots: { flexDirection: 'row', justifyContent: 'center', marginTop: 24 },
  dot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: '#bdbdbd',
    marginHorizontal: 6,
  },
  dotPassed: { backgroundColor: '#1b5e20' },
  primaryButton: {
    backgroundColor: '#1b5e20',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  primaryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
});
