/**
 * Root component + the flow state machine (design doc §3, staged per the
 * 2026-08-31 owner rulings).
 *
 * identity → otp → consent → document → liveness → processing → verdict
 *
 * STAGE GATES (structural, tested):
 *  - the OTP step exists only after an enrollment id exists (the backend sent
 *    a code to the T24-registered mobile — no anchor, no code);
 *  - camera-bearing steps ('document', 'liveness') exist only in states
 *    carrying a consentVersion, and only CONSENT_RECORDED can introduce one —
 *    no consent, no camera, by construction.
 */

import React, { useEffect, useReducer } from 'react';
import { SafeAreaView, StyleSheet } from 'react-native';
import {
  createFaceVerifyClient,
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
import { OtpScreen } from './screens/OtpScreen';
import { ProcessingScreen } from './screens/ProcessingScreen';
import { VerdictScreen } from './screens/VerdictScreen';
import { WelcomeConsentScreen } from './screens/WelcomeConsentScreen';

// -- flow state machine (pure — fully jest-tested) -----------------------------

export type FlowState =
  | { step: 'identity' }
  | { step: 'otp-request'; identity: IdentityInfo }
  | { step: 'otp'; identity: IdentityInfo; enrollmentId: string; mobileHint: string }
  | { step: 'consent'; identity: IdentityInfo; enrollmentId: string }
  | { step: 'document'; identity: IdentityInfo; enrollmentId: string; consentVersion: string }
  | { step: 'liveness'; identity: IdentityInfo; enrollmentId: string; consentVersion: string }
  | { step: 'processing'; identity: IdentityInfo; enrollmentId: string; consentVersion: string }
  | {
      step: 'verdict';
      verdict: Verdict;
      reason: 'match' | 'liveness' | 'error';
      identity: IdentityInfo;
      enrollmentId: string;
      consentVersion: string;
    };

export type FlowAction =
  | { type: 'IDENTITY_SUBMITTED'; identity: IdentityInfo }
  | { type: 'ENROLLMENT_CREATED'; enrollmentId: string; mobileHint: string }
  | { type: 'OTP_VERIFIED' }
  | { type: 'CONSENT_RECORDED'; consentVersion: string }
  | { type: 'DOCUMENT_CAPTURED' }
  | { type: 'LIVENESS_PASSED' }
  | { type: 'LIVENESS_EXHAUSTED' }
  | { type: 'VERDICT_RECEIVED'; verdict: Verdict }
  | { type: 'FLOW_ERROR' }
  | { type: 'RETRY' }
  | { type: 'RESTART' };

export const initialFlowState: FlowState = { step: 'identity' };

export function reduceFlow(state: FlowState, action: FlowAction): FlowState {
  // RESTART is always legal — the only way back to the identity step.
  if (action.type === 'RESTART') return initialFlowState;

  switch (state.step) {
    case 'identity':
      return action.type === 'IDENTITY_SUBMITTED'
        ? { step: 'otp-request', identity: action.identity }
        : state;
    case 'otp-request':
      if (action.type === 'ENROLLMENT_CREATED') {
        return {
          step: 'otp',
          identity: state.identity,
          enrollmentId: action.enrollmentId,
          mobileHint: action.mobileHint,
        };
      }
      if (action.type === 'FLOW_ERROR') {
        return {
          step: 'verdict',
          verdict: 'retry',
          reason: 'error',
          identity: state.identity,
          enrollmentId: '',
          consentVersion: '',
        };
      }
      return state;
    case 'otp':
      return action.type === 'OTP_VERIFIED'
        ? { step: 'consent', identity: state.identity, enrollmentId: state.enrollmentId }
        : state;
    case 'consent':
      return action.type === 'CONSENT_RECORDED'
        ? {
            step: 'document',
            identity: state.identity,
            enrollmentId: state.enrollmentId,
            consentVersion: action.consentVersion,
          }
        : state;
    case 'document':
      return action.type === 'DOCUMENT_CAPTURED'
        ? {
            step: 'liveness',
            identity: state.identity,
            enrollmentId: state.enrollmentId,
            consentVersion: state.consentVersion,
          }
        : state;
    case 'liveness':
      if (action.type === 'LIVENESS_PASSED') {
        return {
          step: 'processing',
          identity: state.identity,
          enrollmentId: state.enrollmentId,
          consentVersion: state.consentVersion,
        };
      }
      if (action.type === 'LIVENESS_EXHAUSTED') {
        return {
          step: 'verdict',
          verdict: 'retry',
          reason: 'liveness',
          identity: state.identity,
          enrollmentId: state.enrollmentId,
          consentVersion: state.consentVersion,
        };
      }
      return state;
    case 'processing':
      if (action.type === 'VERDICT_RECEIVED') {
        return {
          step: 'verdict',
          verdict: action.verdict,
          reason: 'match',
          identity: state.identity,
          enrollmentId: state.enrollmentId,
          consentVersion: state.consentVersion,
        };
      }
      if (action.type === 'FLOW_ERROR') {
        return {
          step: 'verdict',
          verdict: 'retry',
          reason: 'error',
          identity: state.identity,
          enrollmentId: state.enrollmentId,
          consentVersion: state.consentVersion,
        };
      }
      return state;
    case 'verdict':
      return action.type === 'RETRY'
        ? {
            step: 'liveness',
            identity: state.identity,
            enrollmentId: state.enrollmentId,
            consentVersion: state.consentVersion,
          }
        : state;
  }
}

// -- processing pipeline --------------------------------------------------------

async function resolveDefaultExtractor(): Promise<EmbeddingExtractor> {
  try {
    return await TfliteEmbeddingExtractor.load();
  } catch {
    return new StubEmbeddingExtractor();
  }
}

/**
 * Extract → seal → face upload (the enrollment is ALREADY stage-complete at
 * this point) → verify. Any failure dispatches FLOW_ERROR (fail closed).
 */
async function runProcessingPipeline(
  client: FaceVerifyClient,
  extractor: EmbeddingExtractor,
  enrollmentId: string,
  nationalId: string,
): Promise<Verdict> {
  const embedding = await extractor.extractEmbedding(getLatestFaceCrop() ?? 'skeleton-frame');
  const embeddingEnc = seal(encodeEmbeddingForWire(embedding));
  const face = await client.submitEnrollmentFace(enrollmentId, embeddingEnc);
  if (face.status !== 'enrolled') throw new Error(`face upload refused: ${face.status}`);
  const { verdict } = await client.verifyFace(nationalId, embeddingEnc);
  return verdict;
}

// -- root component ---------------------------------------------------------------

export interface AppProps {
  client?: FaceVerifyClient;
  extractor?: EmbeddingExtractor;
}

export default function App({ client, extractor }: AppProps): React.JSX.Element {
  const [state, dispatch] = useReducer(reduceFlow, initialFlowState);
  const api = client ?? createFaceVerifyClient();

  // enrollment request fires on entering otp-request
  useEffect(() => {
    if (state.step !== 'otp-request') return;
    let cancelled = false;
    api
      .createEnrollment({ nationalId: state.identity.nationalId })
      .then((res) => {
        if (!cancelled) {
          dispatch({
            type: 'ENROLLMENT_CREATED',
            enrollmentId: res.enrollment_id,
            mobileHint: res.mobile_hint,
          });
        }
      })
      .catch(() => {
        if (!cancelled) dispatch({ type: 'FLOW_ERROR' });
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.step]);

  useEffect(() => {
    if (state.step !== 'processing') return;
    let cancelled = false;
    (extractor ? Promise.resolve(extractor) : resolveDefaultExtractor())
      .then((resolved) =>
        runProcessingPipeline(api, resolved, state.enrollmentId, state.identity.nationalId),
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.step]);

  return (
    <SafeAreaView style={styles.root}>
      {state.step === 'identity' && (
        <IdentityScreen
          onSubmit={(identity) => dispatch({ type: 'IDENTITY_SUBMITTED', identity })}
        />
      )}
      {state.step === 'otp' && (
        <OtpScreen
          mobileHint={state.mobileHint}
          onVerify={async (code) => {
            await api.verifyEnrollmentOtp(state.enrollmentId, code);
            dispatch({ type: 'OTP_VERIFIED' });
          }}
          onResend={async () => {
            await api.createEnrollment({ nationalId: state.identity.nationalId });
          }}
        />
      )}
      {state.step === 'consent' && (
        <WelcomeConsentScreen
          consentVersion={CONSENT_VERSION}
          onAccept={async () => {
            try {
              await api.recordConsent(state.enrollmentId, CONSENT_VERSION);
              dispatch({ type: 'CONSENT_RECORDED', consentVersion: CONSENT_VERSION });
            } catch {
              dispatch({ type: 'FLOW_ERROR' });
            }
          }}
          onDecline={() => dispatch({ type: 'RESTART' })}
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
