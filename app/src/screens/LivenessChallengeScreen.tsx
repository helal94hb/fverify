/**
 * Guided liveness — the randomized challenge loop UI (design §3/§5).
 *
 * One challenge at a time (blink / turn-left / turn-right), each with its own
 * time window, progress visible throughout. All logic lives in the PURE
 * engine (../liveness/engine.ts); this screen only renders engine snapshots
 * and forwards the designed retry.
 *
 * DETECTOR WIRING POINT: signals arrive through the injected SignalDetector
 * interface. Today the default is `stubSignalDetector`, which NEVER emits —
 * honest placeholder, so on a real device this screen will time out and offer
 * retry until the real detector lands. Next iteration: an ML Kit face
 * detector running in the vision-camera frame processor (front camera)
 * classifies blink/head-pose per frame and calls emit(signal); the frame
 * processor worklet reaches JS via runOnJS.
 */

import React, { useEffect, useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import {
  LivenessEngine,
  LivenessSnapshot,
  type Challenge,
  type SignalDetector,
} from '../liveness/engine';

const CHALLENGE_COPY: Record<Challenge, string> = {
  blink: 'Blink your eyes',
  'turn-left': 'Slowly turn your head to the left',
  'turn-right': 'Slowly turn your head to the right',
};

/**
 * PRE-DETECTOR STAND-IN: a SignalDetector that observes nothing. Clearly a
 * stub — the real one is the face-signal classifier in the frame processor.
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
  detector = stubSignalDetector,
  perChallengeTimeoutMs,
  onPassed,
  onExhausted,
}: LivenessChallengeScreenProps): React.JSX.Element {
  const [snapshot, setSnapshot] = useState<LivenessSnapshot | null>(null);
  const engineRef = useRef<LivenessEngine | null>(null);

  useEffect(() => {
    const engine = new LivenessEngine({
      detector,
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
  progress: { fontSize: 14, opacity: 0.7, textAlign: 'center', marginBottom: 24 },
  body: { fontSize: 15, lineHeight: 22, textAlign: 'center', marginBottom: 24 },
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
