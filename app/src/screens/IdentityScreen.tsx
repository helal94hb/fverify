/**
 * Identity — the self-asserted credentials (owner ruling 2026-08-31: PURE
 * IDENTITY — this blackbox knows username, credential, face, OTP only; the
 * username ↔ customer_id linkage lives in the mobile DB via Agentys, never
 * here — and the 2026-09-02 OTP dispatch refactor: this enrollment only
 * creates the record, the code is minted by the generate call that follows).
 */

import React, { useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';

export interface IdentityInfo {
  username: string;
  password: string;
  mobile: string;
}

export interface IdentityScreenProps {
  onSubmit: (identity: IdentityInfo) => void;
}

export function IdentityScreen({ onSubmit }: IdentityScreenProps): React.JSX.Element {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mobile, setMobile] = useState('');
  // mirror the backend's field minimums (EnrollRequest: 3 / 8 / 5)
  const ready =
    username.trim().length >= 3 && password.length >= 8 && mobile.trim().length >= 5;

  return (
    <View style={styles.container} testID="identity-screen">
      <Text style={styles.title}>Confirm your identity</Text>
      <Text style={styles.label}>Username</Text>
      <TextInput
        style={styles.input}
        testID="username-input"
        value={username}
        onChangeText={setUsername}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="visible-password"
        placeholder="Username"
      />
      <Text style={styles.label}>Password</Text>
      <TextInput
        style={styles.input}
        testID="password-input"
        value={password}
        onChangeText={setPassword}
        autoCapitalize="none"
        autoCorrect={false}
        secureTextEntry
        placeholder="Password"
      />
      <Text style={styles.label}>Mobile</Text>
      <TextInput
        style={styles.input}
        testID="mobile-input"
        value={mobile}
        onChangeText={setMobile}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="phone-pad"
        placeholder="Registered mobile number"
      />
      <Pressable
        style={[styles.primaryButton, !ready && styles.disabled]}
        testID="identity-submit-button"
        disabled={!ready}
        onPress={() =>
          onSubmit({
            username: username.trim(),
            password,
            mobile: mobile.trim(),
          })
        }
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
