/**
 * The sealed backend client — the ONLY module that speaks HTTP to the
 * standalone face-verify backend (base URL comes from ./config).
 *
 * Contract (INTEGRATION.md — the staged enrollment, owner rulings 2026-08-31):
 *   POST /api/v1/enrollments
 *       {national_id} → {enrollment_id, status:'awaiting_otp', mobile_hint}
 *   POST /api/v1/enrollments/{id}/otp {otp_code} → {status:'awaiting_consent'}
 *   POST /api/v1/enrollments/{id}/consent {consent_version} → {status:'awaiting_face'}
 *   POST /api/v1/enrollments/{id}/face {embedding_enc} → {status:'enrolled'}
 *   GET  /api/v1/enrollments/by-national-id/{id}/status
 *       → {enrolled, enrolled_at, customer_id, status}
 *   POST /api/v1/verifications
 *       {national_id | customer_id, embedding_enc} → {verdict, score, threshold}
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
}

export interface CreateEnrollmentResponse {
  enrollment_id: string;
  status: string;
  /** the masked REGISTERED mobile the OTP went to (never the full number) */
  mobile_hint: string;
}

export interface StageResponse {
  status: string;
}

export interface SubmitFaceResponse {
  status: 'enrolled' | string;
}

export interface EnrollmentStatusResponse {
  /** The backend's actual shape — enrolled flag + ISO timestamp (or null). */
  enrolled: boolean;
  enrolled_at: string | null;
  /** the T24 anchor (when resolved) + the enrollment's stage */
  customer_id: string | null;
  status: string | null;
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
  verifyEnrollmentOtp(enrollmentId: string, otpCode: string): Promise<StageResponse>;
  recordConsent(enrollmentId: string, consentVersion: string): Promise<StageResponse>;
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
      }),
    verifyEnrollmentOtp: (enrollmentId, otpCode) =>
      request('POST', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/otp`, {
        otp_code: otpCode,
      }),
    recordConsent: (enrollmentId, consentVersion) =>
      request('POST', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/consent`, {
        consent_version: consentVersion,
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
