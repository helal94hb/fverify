/**
 * Flow state machine — the staged gates (owner rulings 2026-08-31): identity → otp-request → otp → consent → document →
 * liveness → processing → verdict. Camera steps are impossible before CONSENT_RECORDED;
 * the OTP step exists only with an enrollment id; a wrong-code error stays INLINE on the
 * OTP step. Render test proves the consent gate in the real component tree.
 */

import React from 'react';
import TestRenderer, { act } from 'react-test-renderer';
import App, { initialFlowState, reduceFlow, type FlowState } from '../src/App';
import type { IdentityInfo } from '../src/screens/IdentityScreen';

const identity: IdentityInfo = { nationalId: 'TEST-ID-0001' };
const ENROLLMENT = { enrollmentId: 'enr-1', mobileHint: '*** *** 000' };

/** Walk the machine to the document step via every legitimate gate. */
function documentState(): FlowState {
  let state = reduceFlow(initialFlowState, { type: 'IDENTITY_SUBMITTED', identity });
  state = reduceFlow(state, { type: 'ENROLLMENT_CREATED', ...ENROLLMENT });
  state = reduceFlow(state, { type: 'OTP_VERIFIED' });
  return reduceFlow(state, { type: 'CONSENT_RECORDED', consentVersion: '1.0' });
}

function livenessState(): FlowState {
  return reduceFlow(documentState(), { type: 'DOCUMENT_CAPTURED' });
}

describe('flow state machine — the staged gates', () => {
  it('starts at identity and camera actions are ignored everywhere before consent', () => {
    expect(initialFlowState.step).toBe('identity');
    const cameraActions = [
      { type: 'DOCUMENT_CAPTURED' },
      { type: 'LIVENESS_PASSED' },
      { type: 'LIVENESS_EXHAUSTED' },
      { type: 'VERDICT_RECEIVED', verdict: 'verified' },
    ] as const;
    for (const action of cameraActions) {
      expect(reduceFlow(initialFlowState, action)).toBe(initialFlowState);
    }
  });

  it('the otp step exists only after an enrollment id exists', () => {
    const atOtpRequest = reduceFlow(initialFlowState, { type: 'IDENTITY_SUBMITTED', identity });
    expect(atOtpRequest.step).toBe('otp-request');
    const atOtp = reduceFlow(atOtpRequest, { type: 'ENROLLMENT_CREATED', ...ENROLLMENT });
    expect(atOtp.step).toBe('otp');
    expect(atOtp).toMatchObject({ enrollmentId: 'enr-1', mobileHint: '*** *** 000' });
    // no enrollment, no OTP step
    expect(reduceFlow(initialFlowState, { type: 'OTP_VERIFIED' })).toBe(initialFlowState);
  });

  it('no camera before CONSENT_RECORDED — consent can only follow the verified OTP', () => {
    const atOtp = reduceFlow(
      reduceFlow(initialFlowState, { type: 'IDENTITY_SUBMITTED', identity }),
      { type: 'ENROLLMENT_CREATED', ...ENROLLMENT },
    );
    // camera actions ignored at the otp step
    expect(reduceFlow(atOtp, { type: 'DOCUMENT_CAPTURED' })).toBe(atOtp);
    expect(reduceFlow(atOtp, { type: 'LIVENESS_PASSED' })).toBe(atOtp);
    // consent can only follow the verified OTP (not before it)
    const atIdentity = reduceFlow(initialFlowState, { type: 'IDENTITY_SUBMITTED', identity });
    expect(reduceFlow(atIdentity, { type: 'CONSENT_RECORDED', consentVersion: '1.0' })).toBe(
      atIdentity,
    );
  });

  it('walks the full staged path to the verdict', () => {
    let state: FlowState = initialFlowState;
    state = reduceFlow(state, { type: 'IDENTITY_SUBMITTED', identity });
    expect(state.step).toBe('otp-request');
    state = reduceFlow(state, { type: 'ENROLLMENT_CREATED', ...ENROLLMENT });
    expect(state.step).toBe('otp');
    state = reduceFlow(state, { type: 'OTP_VERIFIED' });
    expect(state.step).toBe('consent');
    state = reduceFlow(state, { type: 'CONSENT_RECORDED', consentVersion: '1.0' });
    expect(state.step).toBe('document');
    state = reduceFlow(state, { type: 'DOCUMENT_CAPTURED' });
    expect(state.step).toBe('liveness');
    state = reduceFlow(state, { type: 'LIVENESS_PASSED' });
    expect(state.step).toBe('processing');
    state = reduceFlow(state, { type: 'VERDICT_RECEIVED', verdict: 'verified' });
    expect(state).toMatchObject({ step: 'verdict', verdict: 'verified', reason: 'match' });
  });

  it('liveness exhaustion lands on the designed retry verdict, and retry returns to liveness', () => {
    let state = livenessState();
    state = reduceFlow(state, { type: 'LIVENESS_EXHAUSTED' });
    expect(state).toMatchObject({ step: 'verdict', verdict: 'retry', reason: 'liveness' });
    state = reduceFlow(state, { type: 'RETRY' });
    expect(state.step).toBe('liveness');
  });

  it('a processing failure maps to retry-with-error, never to verified', () => {
    let state = livenessState();
    state = reduceFlow(state, { type: 'LIVENESS_PASSED' });
    state = reduceFlow(state, { type: 'FLOW_ERROR' });
    expect(state).toMatchObject({ step: 'verdict', verdict: 'retry', reason: 'error' });
  });

  it('RESTART is always legal and returns to identity', () => {
    const deep = reduceFlow(livenessState(), { type: 'LIVENESS_PASSED' });
    expect(reduceFlow(deep, { type: 'RESTART' })).toEqual(initialFlowState);
  });
});

describe('App — the staged gates in the rendered tree', () => {
  const fakeClient = {
    createEnrollment: jest.fn(async () => ({
      enrollment_id: 'enr-1',
      status: 'awaiting_otp',
      mobile_hint: '*** *** 000',
    })),
    verifyEnrollmentOtp: jest.fn(async () => ({ status: 'awaiting_consent' })),
    recordConsent: jest.fn(async () => ({ status: 'awaiting_face' })),
    submitEnrollmentFace: jest.fn(async () => ({ status: 'enrolled' })),
    getEnrollmentStatusByNationalId: jest.fn(async () => ({
      enrolled: false,
      enrolled_at: null,
      customer_id: null,
      status: null,
    })),
    verifyFace: jest.fn(async () => ({ verdict: 'verified' as const, score: 0.9, threshold: 0.8 })),
  };

  it('renders identity first; OTP arrives after the enrollment effect; camera waits for consent', async () => {
    let tree: TestRenderer.ReactTestRenderer;
    await act(async () => {
      tree = TestRenderer.create(<App client={fakeClient as never} />);
    });
    const root = tree!.root;

    expect(root.findByProps({ testID: 'identity-screen' })).toBeTruthy();
    expect(root.findAllByProps({ testID: 'otp-screen' })).toHaveLength(0);

    act(() => {
      root.findByProps({ testID: 'national-id-input' }).props.onChangeText('TEST-ID-0001');
    });
    await act(async () => {
      root.findByProps({ testID: 'identity-submit-button' }).props.onPress();
    });
    // the enrollment effect fires and the OTP step arrives with the hint
    expect(root.findByProps({ testID: 'otp-screen' })).toBeTruthy();
    expect((root.findByProps({ testID: 'otp-hint' }).props.children as string[]).join('')).toContain('*** *** 000');
    // and still NO camera — consent has not been recorded
    expect(root.findAllByProps({ testID: 'document-capture-screen' })).toHaveLength(0);
    expect(root.findAllByProps({ testID: 'liveness-screen' })).toHaveLength(0);
  });
});
