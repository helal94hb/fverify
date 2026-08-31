/**
 * Root component + the flow state machine (design doc §3).
 *
 * consent → identity → document → liveness → processing → verdict
 *
 * CONSENT GATE (structural, tested): camera-bearing steps ('document',
 * 'liveness') exist only in states that carry a consentVersion, and only
 * CONSENT_ACCEPTED can introduce one — no consent, no camera screens, by
 * construction of the reducer below.
 *
 * Phase-A demo path in the processing step: extract the embedding on-device,
 * seal it, ensure an enrollment exists for the national ID, then ask the
 * backend for the verdict — the full enroll→verify pipeline in one run.
 * Production splits enrollment (once) from verification (anytime) into
 * separate sessions; that split is a product decision, not made here.
 */

import React, { useEffect, useReducer } from 'react';
import { SafeAreaView, StyleSheet } from 'react-native';
import {
  createFaceVerifyClient,
  isEnrolled,
  type FaceVerifyClient,
  type Verdict,
} from './api';
import { CONSENT_VERSION } from './config';
import {
  StubEmbeddingExtractor,
  encodeEmbeddingForWire,
  type EmbeddingExtractor,
} from './ml/embedding';
import { seal } from './ml/seal';
import { getLatestFaceCrop, TfliteEmbeddingExtractor } from './ml/tfliteExtractor';
import { DocumentCaptureScreen } from './screens/DocumentCaptureScreen';
import { IdentityScreen, type IdentityInfo } from './screens/IdentityScreen';
import { LivenessChallengeScreen } from './screens/LivenessChallengeScreen';
import { ProcessingScreen } from './screens/ProcessingScreen';
import { VerdictScreen } from './screens/VerdictScreen';
import { WelcomeConsentScreen } from './screens/WelcomeConsentScreen';

// -- flow state machine (pure — fully jest-tested) -----------------------------

export type FlowState =
  | { step: 'consent' }
  | { step: 'identity'; consentVersion: string }
  | { step: 'document'; consentVersion: string; identity: IdentityInfo }
  | { step: 'liveness'; consentVersion: string; identity: IdentityInfo }
  | { step: 'processing'; consentVersion: string; identity: IdentityInfo }
  | {
      step: 'verdict';
      verdict: Verdict;
      reason: 'match' | 'liveness' | 'error';
      consentVersion: string;
      identity: IdentityInfo;
    };

export type FlowAction =
  | { type: 'CONSENT_ACCEPTED'; consentVersion: string }
  | { type: 'IDENTITY_SUBMITTED'; identity: IdentityInfo }
  | { type: 'DOCUMENT_CAPTURED' }
  | { type: 'LIVENESS_PASSED' }
  | { type: 'LIVENESS_EXHAUSTED' }
  | { type: 'VERDICT_RECEIVED'; verdict: Verdict }
  | { type: 'FLOW_ERROR' }
  | { type: 'RETRY' }
  | { type: 'RESTART' };

export const initialFlowState: FlowState = { step: 'consent' };

export function reduceFlow(state: FlowState, action: FlowAction): FlowState {
  // RESTART is always legal — it is the only way back to the consent gate.
  if (action.type === 'RESTART') return initialFlowState;

  switch (state.step) {
    case 'consent':
      // The ONLY transition out of the gate. Every camera action is ignored
      // here — no consent, no camera.
      return action.type === 'CONSENT_ACCEPTED'
        ? { step: 'identity', consentVersion: action.consentVersion }
        : state;
    case 'identity':
      return action.type === 'IDENTITY_SUBMITTED'
        ? { step: 'document', consentVersion: state.consentVersion, identity: action.identity }
        : state;
    case 'document':
      return action.type === 'DOCUMENT_CAPTURED'
        ? { step: 'liveness', consentVersion: state.consentVersion, identity: state.identity }
        : state;
    case 'liveness':
      if (action.type === 'LIVENESS_PASSED') {
        return { step: 'processing', consentVersion: state.consentVersion, identity: state.identity };
      }
      if (action.type === 'LIVENESS_EXHAUSTED') {
        return {
          step: 'verdict',
          verdict: 'retry',
          reason: 'liveness',
          consentVersion: state.consentVersion,
          identity: state.identity,
        };
      }
      return state;
    case 'processing':
      if (action.type === 'VERDICT_RECEIVED') {
        return {
          step: 'verdict',
          verdict: action.verdict,
          reason: 'match',
          consentVersion: state.consentVersion,
          identity: state.identity,
        };
      }
      if (action.type === 'FLOW_ERROR') {
        // Fail closed: any pipeline failure renders retry, never "verified".
        return {
          step: 'verdict',
          verdict: 'retry',
          reason: 'error',
          consentVersion: state.consentVersion,
          identity: state.identity,
        };
      }
      return state;
    case 'verdict':
      return action.type === 'RETRY'
        ? { step: 'liveness', consentVersion: state.consentVersion, identity: state.identity }
        : state;
  }
}

// -- processing pipeline --------------------------------------------------------

/**
 * The default extractor: the REAL on-device model when it loads, the
 * deterministic stub when it cannot (emulator / jest / missing native
 * runtime). PHASE-A DEMO FALLBACK — the stub keeps the enroll→verify pipeline
 * exercisable end to end without a camera, but it has no biometric meaning;
 * production must hard-fail here instead of falling back (Phase B hardening).
 */
async function resolveDefaultExtractor(): Promise<EmbeddingExtractor> {
  try {
    return await TfliteEmbeddingExtractor.load();
  } catch {
    return new StubEmbeddingExtractor();
  }
}

/**
 * Extract → seal → enroll-if-needed → verify. Any failure dispatches
 * FLOW_ERROR (fail closed). The frame argument is the freshest face crop
 * captured by the liveness frame processor (the runOnJS mailbox); when no
 * crop exists (stub path) the stub extractor still maps the placeholder
 * deterministically, and the real extractor refuses it — fail closed.
 */
async function runProcessingPipeline(
  client: FaceVerifyClient,
  extractor: EmbeddingExtractor,
  identity: IdentityInfo,
  consentVersion: string,
): Promise<Verdict> {
  const embedding = await extractor.extractEmbedding(getLatestFaceCrop() ?? 'skeleton-frame');
  const embeddingEnc = seal(encodeEmbeddingForWire(embedding));
  const status = await client.getEnrollmentStatusByNationalId(identity.nationalId);
  if (!isEnrolled(status)) {
    const { enrollment_id } = await client.createEnrollment({
      nationalId: identity.nationalId,
      mobile: identity.mobile,
      consentVersion,
    });
    await client.submitEnrollmentFace(enrollment_id, embeddingEnc);
  }
  const { verdict } = await client.verifyFace(identity.nationalId, embeddingEnc);
  return verdict;
}

// -- root component ---------------------------------------------------------------

export interface AppProps {
  /** Test seams — production resolves the real extractor (see resolveDefaultExtractor). */
  client?: FaceVerifyClient;
  extractor?: EmbeddingExtractor;
}

export default function App({ client, extractor }: AppProps): React.JSX.Element {
  const [state, dispatch] = useReducer(reduceFlow, initialFlowState);

  useEffect(() => {
    if (state.step !== 'processing') return;
    let cancelled = false;
    (extractor ? Promise.resolve(extractor) : resolveDefaultExtractor())
      .then((resolved) =>
        runProcessingPipeline(
          client ?? createFaceVerifyClient(),
          resolved,
          state.identity,
          state.consentVersion,
        ),
      )
      .then((verdict) => {
        if (!cancelled) dispatch({ type: 'VERDICT_RECEIVED', verdict });
      })
      .catch(() => {
        if (!cancelled) dispatch({ type: 'FLOW_ERROR' });
      });
    return () => {
      cancelled = true;
    };
  }, [state, client, extractor]);

  return (
    <SafeAreaView style={styles.root}>
      {state.step === 'consent' && (
        <WelcomeConsentScreen
          consentVersion={CONSENT_VERSION}
          onAccept={() => dispatch({ type: 'CONSENT_ACCEPTED', consentVersion: CONSENT_VERSION })}
          onDecline={() => dispatch({ type: 'RESTART' })}
        />
      )}
      {state.step === 'identity' && (
        <IdentityScreen
          onSubmit={(identity) => dispatch({ type: 'IDENTITY_SUBMITTED', identity })}
        />
      )}
      {state.step === 'document' && (
        <DocumentCaptureScreen onCaptured={() => dispatch({ type: 'DOCUMENT_CAPTURED' })} />
      )}
      {state.step === 'liveness' && (
        <LivenessChallengeScreen
          onPassed={() => dispatch({ type: 'LIVENESS_PASSED' })}
          onExhausted={() => dispatch({ type: 'LIVENESS_EXHAUSTED' })}
        />
      )}
      {state.step === 'processing' && <ProcessingScreen />}
      {state.step === 'verdict' && (
        <VerdictScreen
          verdict={state.verdict}
          reason={state.reason}
          onRetry={() => dispatch({ type: 'RETRY' })}
          onDone={() => dispatch({ type: 'RESTART' })}
        />
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
});
