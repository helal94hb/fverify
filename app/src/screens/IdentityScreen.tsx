/**
 * Self-asserted identity — national ID + mobile (PoC posture, design §7
 * decision 1: production needs a real identity anchor; nothing here silently
 * resolves that). Validation is minimal and honest: both fields required.
 */

import React, { useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';

export interface IdentityInfo {
  nationalId: string;
  mobile: string;
}

export interface IdentityScreenProps {
  onSubmit: (identity: IdentityInfo) => void;
}

export function IdentityScreen({ onSubmit }: IdentityScreenProps): React.JSX.Element {
  const [nationalId, setNationalId] = useState('');
  const [mobile, setMobile] = useState('');
  const ready = nationalId.trim().length > 0 && mobile.trim().length > 0;

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
      <Text style={styles.label}>Mobile number</Text>
      <TextInput
        style={styles.input}
        testID="mobile-input"
        value={mobile}
        onChangeText={setMobile}
        keyboardType="phone-pad"
        placeholder="Mobile number"
      />
      <Pressable
        style={[styles.primaryButton, !ready && styles.disabled]}
        testID="identity-submit-button"
        disabled={!ready}
        onPress={() => onSubmit({ nationalId: nationalId.trim(), mobile: mobile.trim() })}
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
