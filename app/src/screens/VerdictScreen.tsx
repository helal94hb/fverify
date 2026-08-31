/**
 * Verdict — renders the SERVER's verdict (verified / rejected / retry).
 * The 'retry' variant also serves the liveness-exhausted and transport-error
 * paths; those are NOT match verdicts, so the copy says exactly what happened
 * instead of implying the server rejected a face (honest limits, design §6).
 */

import React from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import type { Verdict } from '../api';

export interface VerdictScreenProps {
  verdict: Verdict;
  /** Why a retry is being offered — 'match' (server said so) or 'liveness'/'error'. */
  reason: 'match' | 'liveness' | 'error';
  onRetry: () => void;
  onDone: () => void;
}

export function VerdictScreen({
  verdict,
  reason,
  onRetry,
  onDone,
}: VerdictScreenProps): React.JSX.Element {
  return (
    <View style={styles.container} testID="verdict-screen">
      {verdict === 'verified' && (
        <>
          <Text style={styles.verified} testID="verdict-verified">
            Verified
          </Text>
          <Text style={styles.body}>Your identity was confirmed.</Text>
          <Pressable style={styles.primaryButton} testID="verdict-done-button" onPress={onDone}>
            <Text style={styles.primaryButtonText}>Done</Text>
          </Pressable>
        </>
      )}
      {verdict === 'rejected' && (
        <>
          <Text style={styles.rejected} testID="verdict-rejected">
            Not verified
          </Text>
          <Text style={styles.body}>
            We could not match you to the enrolled face. If you believe this is a mistake,
            please try again in good light.
          </Text>
          <Pressable style={styles.primaryButton} testID="verdict-retry-button" onPress={onRetry}>
            <Text style={styles.primaryButtonText}>Try again</Text>
          </Pressable>
        </>
      )}
      {verdict === 'retry' && (
        <>
          <Text style={styles.retryTitle} testID="verdict-retry">
            Let's try that again
          </Text>
          <Text style={styles.body}>
            {reason === 'liveness'
              ? 'The liveness challenges were not completed in time.'
              : reason === 'error'
                ? 'We could not reach the verification service.'
                : 'The check did not complete.'}
          </Text>
          <Pressable style={styles.primaryButton} testID="verdict-retry-button" onPress={onRetry}>
            <Text style={styles.primaryButtonText}>Try again</Text>
          </Pressable>
          <Pressable style={styles.secondaryButton} testID="verdict-done-button" onPress={onDone}>
            <Text style={styles.secondaryButtonText}>Cancel</Text>
          </Pressable>
        </>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, justifyContent: 'center' },
  verified: { fontSize: 26, fontWeight: '700', color: '#1b5e20', textAlign: 'center' },
  rejected: { fontSize: 26, fontWeight: '700', color: '#b71c1c', textAlign: 'center' },
  retryTitle: { fontSize: 26, fontWeight: '700', textAlign: 'center' },
  body: { fontSize: 15, lineHeight: 22, textAlign: 'center', marginVertical: 24 },
  primaryButton: {
    backgroundColor: '#1b5e20',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  primaryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
  secondaryButton: { paddingVertical: 12, alignItems: 'center', marginTop: 8 },
  secondaryButtonText: { fontSize: 15, opacity: 0.7 },
});
