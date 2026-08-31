/**
 * Welcome + explicit consent — ALWAYS before any camera opens (design §3).
 * The consent gate is enforced structurally by the flow state machine in
 * App.tsx: camera screens are unreachable until CONSENT_ACCEPTED.
 */

import React from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

export interface WelcomeConsentScreenProps {
  consentVersion: string;
  onAccept: () => void;
  onDecline: () => void;
}

export function WelcomeConsentScreen({
  consentVersion,
  onAccept,
  onDecline,
}: WelcomeConsentScreenProps): React.JSX.Element {
  return (
    <View style={styles.container} testID="consent-screen">
      <Text style={styles.title}>Face verification</Text>
      <Text style={styles.body}>
        This app verifies that you are physically present and match your enrolled face.{'\n\n'}
        Before your camera opens, please read and accept:{'\n\n'}
        · Your camera is used only on this device. Photos and video of your face or documents
        are processed on your phone and discarded immediately — they are never uploaded and
        never stored anywhere.{'\n\n'}
        · The only thing sent to the Bank is a mathematical face signature (an embedding
        vector), encrypted in transit.{'\n\n'}
        · Whether it is you is decided by the Bank's server, never by this app.{'\n\n'}
        · You can ask for your enrolled face signature to be deleted at any time.
      </Text>
      <Text style={styles.version} testID="consent-version">
        Consent version {consentVersion}
      </Text>
      <Pressable style={styles.primaryButton} testID="consent-accept-button" onPress={onAccept}>
        <Text style={styles.primaryButtonText}>I understand and agree</Text>
      </Pressable>
      <Pressable style={styles.secondaryButton} testID="consent-decline-button" onPress={onDecline}>
        <Text style={styles.secondaryButtonText}>Not now</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, justifyContent: 'center' },
  title: { fontSize: 24, fontWeight: '700', marginBottom: 16 },
  body: { fontSize: 15, lineHeight: 22, marginBottom: 24 },
  version: { fontSize: 12, opacity: 0.6, marginBottom: 24 },
  primaryButton: {
    backgroundColor: '#1b5e20',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
    marginBottom: 12,
  },
  primaryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
  secondaryButton: { paddingVertical: 12, alignItems: 'center' },
  secondaryButtonText: { fontSize: 15, opacity: 0.7 },
});
