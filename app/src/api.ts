/**
 * The sealed backend client — the ONLY module that speaks HTTP to the
 * standalone face-verify backend (base URL comes from ./config).
 *
 * Contract (design doc §3, backend track):
 *   POST /api/v1/enrollments
 *       {national_id, mobile, consent_version} → {enrollment_id, status}
 *   POST /api/v1/enrollments/{id}/face
 *       {embedding_enc} → {status:'enrolled'}
 *   GET  /api/v1/enrollments/by-national-id/{id}/status
 *       → enrollment status record (treated as enrolled ONLY when the
 *         payload's status field is exactly 'enrolled' — fail closed)
 *   POST /api/v1/verifications
 *       {national_id, embedding_enc} → {verdict, score, threshold}
 *
 * Invariants honored here:
 *   - The ONLY biometric that crosses the wire is `embedding_enc` — an
 *     enc1-sealed compact embedding (see ml/seal.ts + ml/embedding.ts).
 *     No image, no PII beyond the self-asserted identity, ever.
 *   - The match VERDICT is computed server-side; this client transports the
 *     verdict and never second-guesses it.
 *   - Fail closed: transport errors, non-2xx, or unparseable bodies throw
 *     ApiError — the caller renders retry, never "verified".
 */

import { API_BASE_URL } from './config';

export interface CreateEnrollmentRequest {
  nationalId: string;
  mobile: string;
  consentVersion: string;
}

export interface CreateEnrollmentResponse {
  enrollment_id: string;
  status: string;
}

export interface SubmitFaceResponse {
  status: 'enrolled' | string;
}

export interface EnrollmentStatusResponse {
  /** The backend's actual shape — enrolled flag + ISO timestamp (or null). */
  enrolled: boolean;
  enrolled_at: string | null;
}

/** Server-computed verdict values — the device never derives its own. */
export type Verdict = 'verified' | 'rejected' | 'retry';

export interface VerifyResponse {
  verdict: Verdict;
  score: number;
  threshold: number;
}

export interface FaceVerifyClient {
  createEnrollment(req: CreateEnrollmentRequest): Promise<CreateEnrollmentResponse>;
  submitEnrollmentFace(enrollmentId: string, embeddingEnc: string): Promise<SubmitFaceResponse>;
  getEnrollmentStatusByNationalId(nationalId: string): Promise<EnrollmentStatusResponse>;
  verifyFace(nationalId: string, embeddingEnc: string): Promise<VerifyResponse>;
}

/** Client-safe failure — carries a category and HTTP status, never internals. */
export class ApiError extends Error {
  constructor(
    readonly reason: 'network' | 'http' | 'bad-response',
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError('bad-response', res.status, 'response was not valid JSON');
  }
}

function problemMessage(body: unknown, status: number): string {
  // RFC 7807 best-effort: the title is diagnostic, never customer copy.
  if (body && typeof body === 'object') {
    const title = (body as { title?: unknown }).title;
    if (typeof title === 'string' && title) return `HTTP ${status}: ${title}`;
  }
  return `HTTP ${status}`;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
  } catch {
    throw new ApiError('network', 0, 'backend unreachable');
  }
  const parsed = await parseBody(res);
  if (!res.ok) {
    throw new ApiError('http', res.status, problemMessage(parsed, res.status));
  }
  return parsed as T;
}

export function createFaceVerifyClient(): FaceVerifyClient {
  return {
    createEnrollment: (req) =>
      request('POST', '/api/v1/enrollments', {
        national_id: req.nationalId,
        mobile: req.mobile,
        consent_version: req.consentVersion,
      }),
    submitEnrollmentFace: (enrollmentId, embeddingEnc) =>
      request('POST', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/face`, {
        embedding_enc: embeddingEnc,
      }),
    getEnrollmentStatusByNationalId: (nationalId) =>
      request(
        'GET',
        `/api/v1/enrollments/by-national-id/${encodeURIComponent(nationalId)}/status`,
      ),
    verifyFace: (nationalId, embeddingEnc) =>
      request('POST', '/api/v1/verifications', {
        national_id: nationalId,
        embedding_enc: embeddingEnc,
      }),
  };
}

/** True only when the backend explicitly reports an enrolled record. */
export function isEnrolled(status: EnrollmentStatusResponse): boolean {
  return status.enrolled === true;
}
