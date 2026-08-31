/**
 * Flow state machine — the consent gate (no consent → no camera screens),
 * the happy path, retry wiring, and fail-closed error mapping. Reducer tests
 * are pure; the render test proves the gate in the real component tree.
 */

import React from 'react';
import TestRenderer, { act } from 'react-test-renderer';
import App, { initialFlowState, reduceFlow, type FlowState } from '../src/App';
import type { IdentityInfo } from '../src/screens/IdentityScreen';

const identity: IdentityInfo = { nationalId: 'TEST-ID-0001', mobile: '+0000000000' };

/** Walk the machine to the identity step (the only way out of the gate). */
function consentedState(): FlowState {
  return reduceFlow(initialFlowState, { type: 'CONSENT_ACCEPTED', consentVersion: '1.0' });
}

function livenessState(): FlowState {
  const atIdentity = consentedState();
  const atDocument = reduceFlow(atIdentity, { type: 'IDENTITY_SUBMITTED', identity });
  return reduceFlow(atDocument, { type: 'DOCUMENT_CAPTURED' });
}

describe('flow state machine — consent gate', () => {
  it('starts at consent and no camera action escapes the gate', () => {
    expect(initialFlowState.step).toBe('consent');
    const cameraActions = [
      { type: 'IDENTITY_SUBMITTED', identity },
      { type: 'DOCUMENT_CAPTURED' },
      { type: 'LIVENESS_PASSED' },
      { type: 'LIVENESS_EXHAUSTED' },
      { type: 'VERDICT_RECEIVED', verdict: 'verified' },
    ] as const;
    for (const action of cameraActions) {
      // Every non-consent action is ignored — the state is unchanged.
      expect(reduceFlow(initialFlowState, action)).toBe(initialFlowState);
    }
  });

  it('accepting consent opens identity — and only identity (still no camera)', () => {
    const next = reduceFlow(initialFlowState, { type: 'CONSENT_ACCEPTED', consentVersion: '1.0' });
    expect(next.step).toBe('identity');
    expect(next).toMatchObject({ consentVersion: '1.0' });
  });

  it('camera steps are unreachable without identity even after consent', () => {
    const atIdentity = consentedState();
    expect(reduceFlow(atIdentity, { type: 'LIVENESS_PASSED' })).toBe(atIdentity);
    expect(reduceFlow(atIdentity, { type: 'DOCUMENT_CAPTURED' })).toBe(atIdentity);
  });
});

describe('flow state machine — happy path and retry', () => {
  it('walks consent → identity → document → liveness → processing → verdict', () => {
    let state = initialFlowState;
    state = reduceFlow(state, { type: 'CONSENT_ACCEPTED', consentVersion: '1.0' });
    expect(state.step).toBe('identity');
    state = reduceFlow(state, { type: 'IDENTITY_SUBMITTED', identity });
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

  it('RESTART is always legal and returns to the consent gate', () => {
    const deep = reduceFlow(livenessState(), { type: 'LIVENESS_PASSED' });
    expect(reduceFlow(deep, { type: 'RESTART' })).toEqual(initialFlowState);
    expect(reduceFlow(consentedState(), { type: 'RESTART' })).toEqual(initialFlowState);
  });
});

describe('App — consent gate in the rendered tree', () => {
  it('renders consent first; camera screens are absent until consent is given', () => {
    let tree: TestRenderer.ReactTestRenderer;
    act(() => {
      tree = TestRenderer.create(<App />);
    });
    const root = tree!.root;

    expect(root.findByProps({ testID: 'consent-screen' })).toBeTruthy();
    expect(root.findByProps({ testID: 'consent-version' }).props.children).toContain('1.0');
    expect(root.findAllByProps({ testID: 'identity-screen' })).toHaveLength(0);
    expect(root.findAllByProps({ testID: 'document-capture-screen' })).toHaveLength(0);
    expect(root.findAllByProps({ testID: 'liveness-screen' })).toHaveLength(0);

    act(() => {
      root.findByProps({ testID: 'consent-accept-button' }).props.onPress();
    });

    expect(root.findAllByProps({ testID: 'consent-screen' })).toHaveLength(0);
    expect(root.findByProps({ testID: 'identity-screen' })).toBeTruthy();
    // Camera screens still gated — identity has not been submitted.
    expect(root.findAllByProps({ testID: 'document-capture-screen' })).toHaveLength(0);
    expect(root.findAllByProps({ testID: 'liveness-screen' })).toHaveLength(0);
  });
});
