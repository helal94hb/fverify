/**
 * Identity — the national ID only (owner ruling 2026-08-31: the anchor is
 * T24; the core resolves the customer id + the REGISTERED mobile, so the
 * customer never types a phone number here — and nobody can self-assert one).
 */

import React, { useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';

export interface IdentityInfo {
  nationalId: string;
}

export interface IdentityScreenProps {
  onSubmit: (identity: IdentityInfo) => void;
}

export function IdentityScreen({ onSubmit }: IdentityScreenProps): React.JSX.Element {
  const [nationalId, setNationalId] = useState('');
  const ready = nationalId.trim().length >= 8;

  return (
    <View style={styles.container} testID="identity-screen">
      <Text style={styles.title}>Confirm your identity</Text>
      <Text style={styles.label}>National ID</Text>
      <TextInput
        style={styles.input}
        testID="national-id-input"
        value={nationalId}
        onChangeText={setNationalId}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="visible-password"
        placeholder="National ID number"
      />
      <Pressable
        style={[styles.primaryButton, !ready && styles.disabled]}
        testID="identity-submit-button"
        disabled={!ready}
        onPress={() => onSubmit({ nationalId: nationalId.trim() })}
      >
        <Text style={styles.primaryButtonText}>Continue</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, justifyContent: 'center' },
  title: { fontSize: 24, fontWeight: '700', marginBottom: 24 },
  label: { fontSize: 14, marginBottom: 6 },
  input: {
    borderWidth: 1,
    borderColor: '#9e9e9e',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 16,
    marginBottom: 16,
  },
  primaryButton: {
    backgroundColor: '#1b5e20',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 8,
  },
  disabled: { opacity: 0.4 },
  primaryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
});
