/**
 * API client — call shapes against a mocked fetch, fail-closed error paths.
 * Test identities are fake placeholders, never real PII.
 */

import {
  ApiError,
  createFaceVerifyClient,
  isEnrolled,
  type VerifyResponse,
} from '../src/api';
import { API_BASE_URL } from '../src/config';

const fetchMock = jest.fn<Promise<Response>, [string, RequestInit?]>();

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock as unknown as typeof fetch;
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function lastCall(): { url: string; init: RequestInit } {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const [url, init] = fetchMock.mock.calls[0]!;
  return { url, init: init ?? {} };
}

const ENROLL_REQ = { username: 'face.user', password: 'Sup3r#Secret1', mobile: '01000000000' };

describe('FaceVerifyClient — call shapes', () => {
  const client = createFaceVerifyClient();

  it('POST /api/v1/enrollments sends the pure-identity record (snake_case)', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(201, { enrollment_id: 'enr-1', status: 'awaiting_otp', mobile_hint: '*** *** 000' }),
    );

    const res = await client.createEnrollment(ENROLL_REQ);

    expect(res).toEqual({ enrollment_id: 'enr-1', status: 'awaiting_otp', mobile_hint: '*** *** 000' });
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/enrollments`);
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({
      username: 'face.user',
      password: 'Sup3r#Secret1',
      mobile: '01000000000',
    });
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
  });

  it('POST /api/v1/enrollments/{id}/otp/generate mints the code (dispatch export)', async () => {
    const payload = {
      enrollment_id: 'enr-1',
      ciphered_otp: 'aes256gcm:TESTCIPHER',
      mobile: '01000000000',
      mobile_hint: '*** *** 000',
      expires_in: 600,
    };
    fetchMock.mockResolvedValue(jsonResponse(200, payload));

    const res = await client.generateOtp('enr-1');

    expect(res).toEqual(payload);
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/enrollments/enr-1/otp/generate`);
    expect(init.method).toBe('POST');
    expect(init.body).toBeUndefined();
  });

  it('POST /api/v1/enrollments/{id}/otp sends the typed code SEALED (enc1:)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { status: 'awaiting_consent' }));

    const res = await client.verifyEnrollmentOtp('enr-1', '123456');

    expect(res.status).toBe('awaiting_consent');
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/enrollments/enr-1/otp`);
    expect(init.method).toBe('POST');
    const body = JSON.parse(String(init.body));
    // the plaintext code must never appear — only the sealed envelope
    expect(Object.keys(body)).toEqual(['otp_code_enc']);
    expect(body.otp_code_enc).toMatch(/^enc1:/);
    expect(body.otp_code_enc).not.toContain('123456');
  });

  it('POST /api/v1/enrollments/{id}/face sends only the sealed embedding', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { status: 'enrolled' }));

    const res = await client.submitEnrollmentFace('enr-9', 'enc1:TESTSEALED');

    expect(res.status).toBe('enrolled');
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/enrollments/enr-9/face`);
    expect(init.method).toBe('POST');
    const body = JSON.parse(String(init.body));
    expect(Object.keys(body)).toEqual(['embedding_enc']);
    expect(body.embedding_enc).toBe('enc1:TESTSEALED');
  });

  it('GET /api/v1/enrollments/by-username/{username}/status sends no body', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { enrolled: true, enrolled_at: '2026-08-29T00:00:00Z' }));

    const res = await client.getEnrollmentStatusByUsername('face.user');

    expect(isEnrolled(res)).toBe(true);
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/enrollments/by-username/face.user/status`);
    expect(init.method).toBe('GET');
    expect(init.body).toBeUndefined();
  });

  it('POST /api/v1/verifications returns the server verdict untouched', async () => {
    const verdictPayload: VerifyResponse = { verdict: 'verified', score: 0.91, threshold: 0.6 };
    fetchMock.mockResolvedValue(jsonResponse(200, verdictPayload));

    const res = await client.verifyFace('face.user', 'enc1:TESTSEALED');

    expect(res).toEqual(verdictPayload);
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/verifications`);
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({
      username: 'face.user',
      embedding_enc: 'enc1:TESTSEALED',
    });
  });

  it('isEnrolled reads the backend shape ({enrolled}) and fails closed otherwise', () => {
    expect(
      isEnrolled({ enrolled: true, enrolled_at: '2026-08-29T00:00:00Z', status: 'enrolled' }),
    ).toBe(true);
    expect(isEnrolled({ enrolled: false, enrolled_at: null, status: null })).toBe(false);
  });
});

describe('FaceVerifyClient — fail-closed error paths', () => {
  const client = createFaceVerifyClient();

  it('throws ApiError on non-2xx and surfaces the RFC 7807 title', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(429, { title: 'Too Many Requests', status: 429 }),
    );
    const err = await client.verifyFace('face.user', 'enc1:X').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).reason).toBe('http');
    expect((err as ApiError).status).toBe(429);
    expect((err as ApiError).message).toContain('Too Many Requests');
  });

  it('throws ApiError when the network is unreachable', async () => {
    fetchMock.mockRejectedValue(new Error('boom'));
    const err = await client.getEnrollmentStatusByUsername('face.user').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).reason).toBe('network');
    expect((err as ApiError).status).toBe(0);
  });

  it('throws ApiError when a 2xx body is not valid JSON', async () => {
    fetchMock.mockResolvedValue(
      new Response('not-json', { status: 200, headers: { 'Content-Type': 'text/plain' } }),
    );
    const err = await client.verifyFace('face.user', 'enc1:X').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).reason).toBe('bad-response');
  });
});
