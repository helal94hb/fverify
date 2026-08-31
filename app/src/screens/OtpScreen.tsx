/**
 * OTP verification (fverify's own OTP — the code the backend sent to the T24-REGISTERED mobile
 * (owner ruling 2026-08-31). Six boxes, verify, resend (cooldown shown from the server),
 * inline designed errors — a wrong code says so HERE, never as a banner.
 */

import React, { useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';

import { ApiError } from '../api';

export interface OtpScreenProps {
  /** the masked registered mobile, e.g. "*** *** 000" */
  mobileHint: string;
  onVerify: (code: string) => Promise<void>;
  onResend: () => Promise<void>;
}

const OTP_LEN = 6;

export function OtpScreen({ mobileHint, onVerify, onResend }: OtpScreenProps): React.JSX.Element {
  const [boxes, setBoxes] = useState<string[]>(Array.from({ length: OTP_LEN }, () => ''));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cooldownLeft, setCooldownLeft] = useState(60);

  const code = boxes.join('');
  const complete = code.length === OTP_LEN && /^\d{6}$/.test(code);

  const setDigit = (i: number, digit: string) => {
    setError(null);
    setBoxes((prev) => prev.map((v, idx) => (idx === i ? digit.slice(-1) : v)));
  };

  const verify = async () => {
    setBusy(true);
    try {
      await onVerify(code);
    } catch (e) {
      setError(
        e instanceof ApiError && e.status === 422
          ? 'That code is incorrect or expired. Request a new one and try again.'
          : 'Something went wrong. Please try again.',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <View style={styles.container} testID="otp-screen">
      <Text style={styles.title}>Enter the code</Text>
      <Text style={styles.subtitle} testID="otp-hint">
        We sent it to {mobileHint}
      </Text>
      <View style={styles.row}>
        {boxes.map((digit, i) => (
          <TextInput
            key={i}
            style={styles.box}
            testID={`otp-box-${i}`}
            value={digit}
            onChangeText={(d) => setDigit(i, d)}
            keyboardType="number-pad"
            maxLength={1}
          />
        ))}
      </View>
      {error ? (
        <Text style={styles.error} testID="otp-error">
          {error}
        </Text>
      ) : null}
      <Pressable
        style={[styles.primaryButton, (!complete || busy) && styles.disabled]}
        testID="otp-verify-button"
        disabled={!complete || busy}
        onPress={verify}
      >
        <Text style={styles.primaryButtonText}>Verify</Text>
      </Pressable>
      <Pressable
        style={[styles.linkButton, (cooldownLeft > 0 || busy) && styles.disabled]}
        testID="otp-resend-button"
        disabled={cooldownLeft > 0 || busy}
        onPress={async () => {
          setBusy(true);
          try {
            await onResend();
            setCooldownLeft(60);
          } catch {
            setError('Could not resend the code yet. Try again shortly.');
          } finally {
            setBusy(false);
          }
        }}
      >
        <Text style={styles.linkText}>
          {cooldownLeft > 0 ? `Resend available in ${cooldownLeft}s` : 'Resend code'}
        </Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, justifyContent: 'center' },
  title: { fontSize: 24, fontWeight: '700', marginBottom: 8 },
  subtitle: { fontSize: 14, color: '#616161', marginBottom: 24 },
  row: { flexDirection: 'row', gap: 8, justifyContent: 'center', marginBottom: 16 },
  box: {
    borderWidth: 1,
    borderColor: '#9e9e9e',
    borderRadius: 8,
    width: 44,
    height: 52,
    textAlign: 'center',
    fontSize: 20,
  },
  error: { color: '#b3261e', fontSize: 14, marginBottom: 12, textAlign: 'center' },
  primaryButton: {
    backgroundColor: '#1b5e20',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 8,
  },
  disabled: { opacity: 0.4 },
  primaryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
  linkButton: { alignItems: 'center', marginTop: 20, paddingVertical: 8 },
  linkText: { color: '#1b5e20', fontSize: 14, fontWeight: '600' },
});
