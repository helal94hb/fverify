/**
 * Processing — the sealed embedding is on the wire and the SERVER is
 * computing the verdict (design §5: the verdict is never computed on the
 * device). Pure status surface; the work happens in App.tsx's effect.
 */

import React from 'react';
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';

export function ProcessingScreen(): React.JSX.Element {
  return (
    <View style={styles.container} testID="processing-screen">
      <ActivityIndicator size="large" testID="processing-indicator" />
      <Text style={styles.title}>Verifying…</Text>
      <Text style={styles.body}>
        Your encrypted face signature is being checked on the Bank's server. This takes a
        moment.
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, justifyContent: 'center', alignItems: 'center' },
  title: { fontSize: 20, fontWeight: '700', marginTop: 24, marginBottom: 8 },
  body: { fontSize: 15, lineHeight: 22, textAlign: 'center', opacity: 0.8 },
});
