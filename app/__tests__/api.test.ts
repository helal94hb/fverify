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

describe('FaceVerifyClient — call shapes', () => {
  const client = createFaceVerifyClient();

  it('POST /api/v1/enrollments sends identity + consent version (snake_case)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { enrollment_id: 'enr-1', status: 'created' }));

    const res = await client.createEnrollment({
      nationalId: 'TEST-ID-0001',
      mobile: '+0000000000',
      consentVersion: '1.0',
    });

    expect(res).toEqual({ enrollment_id: 'enr-1', status: 'created' });
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/enrollments`);
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({
      national_id: 'TEST-ID-0001',
      mobile: '+0000000000',
      consent_version: '1.0',
    });
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
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

  it('GET /api/v1/enrollments/by-national-id/{id}/status sends no body', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { enrolled: true, enrolled_at: '2026-08-29T00:00:00Z' }));

    const res = await client.getEnrollmentStatusByNationalId('TEST-ID-0001');

    expect(isEnrolled(res)).toBe(true);
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/enrollments/by-national-id/TEST-ID-0001/status`);
    expect(init.method).toBe('GET');
    expect(init.body).toBeUndefined();
  });

  it('POST /api/v1/verifications returns the server verdict untouched', async () => {
    const verdictPayload: VerifyResponse = { verdict: 'verified', score: 0.91, threshold: 0.6 };
    fetchMock.mockResolvedValue(jsonResponse(200, verdictPayload));

    const res = await client.verifyFace('TEST-ID-0001', 'enc1:TESTSEALED');

    expect(res).toEqual(verdictPayload);
    const { url, init } = lastCall();
    expect(url).toBe(`${API_BASE_URL}/api/v1/verifications`);
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({
      national_id: 'TEST-ID-0001',
      embedding_enc: 'enc1:TESTSEALED',
    });
  });

  it('isEnrolled reads the backend shape ({enrolled}) and fails closed otherwise', () => {
    expect(isEnrolled({ enrolled: true, enrolled_at: '2026-08-29T00:00:00Z' })).toBe(true);
    expect(isEnrolled({ enrolled: false, enrolled_at: null })).toBe(false);
  });
});

describe('FaceVerifyClient — fail-closed error paths', () => {
  const client = createFaceVerifyClient();

  it('throws ApiError on non-2xx and surfaces the RFC 7807 title', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(429, { title: 'Too Many Requests', status: 429 }),
    );
    const err = await client.verifyFace('TEST-ID-0001', 'enc1:X').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).reason).toBe('http');
    expect((err as ApiError).status).toBe(429);
    expect((err as ApiError).message).toContain('Too Many Requests');
  });

  it('throws ApiError when the network is unreachable', async () => {
    fetchMock.mockRejectedValue(new Error('boom'));
    const err = await client.getEnrollmentStatusByNationalId('TEST-ID-0001').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).reason).toBe('network');
    expect((err as ApiError).status).toBe(0);
  });

  it('throws ApiError when a 2xx body is not valid JSON', async () => {
    fetchMock.mockResolvedValue(
      new Response('not-json', { status: 200, headers: { 'Content-Type': 'text/plain' } }),
    );
    const err = await client.verifyFace('TEST-ID-0001', 'enc1:X').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).reason).toBe('bad-response');
  });
});
