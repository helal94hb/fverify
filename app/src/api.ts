/**
 * The sealed backend client — the ONLY module that speaks HTTP to the
 * standalone face-verify backend (base URL comes from ./config).
 *
 * Contract (INTEGRATION.md — pure-identity staged enrollment, owner rulings
 * 2026-08-31, + the 3-layer OTP dispatch architecture, team commit 2026-09-02):
 *   POST /api/v1/enrollments
 *       {username, password, mobile} → {enrollment_id, status:'awaiting_otp', mobile_hint}
 *   POST /api/v1/enrollments/{id}/otp/generate
 *       → {enrollment_id, ciphered_otp, mobile, mobile_hint, expires_in}
 *       (dev lane: this call stands in for the Agentys dispatch node — the
 *       ciphered_otp is AES-256-GCM for THAT node; the app never opens it,
 *       the dev code is the known lane stub)
 *   POST /api/v1/enrollments/{id}/otp {otp_code_enc}
 *       → {status:'awaiting_consent'} — the typed code ALWAYS crosses sealed
 *       (enc1:, this module seals it), so no orchestrator can carry cleartext
 *   POST /api/v1/enrollments/{id}/consent {consent_version} → {status:'awaiting_face'}
 *   POST /api/v1/enrollments/{id}/face {embedding_enc} → {status:'enrolled'}
 *   GET  /api/v1/enrollments/by-username/{username}/status
 *       → {enrolled, enrolled_at, status}
 *   POST /api/v1/verifications
 *       {username, embedding_enc} → {verdict, score, threshold}
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
import { seal } from './ml/seal';

export interface CreateEnrollmentRequest {
  username: string;
  password: string;
  mobile: string;
}

export interface CreateEnrollmentResponse {
  enrollment_id: string;
  status: string;
  /** the masked REGISTERED mobile (never the full number) */
  mobile_hint: string;
}

export interface GenerateOtpResponse {
  enrollment_id: string;
  /** AES-256-GCM export for the Agentys dispatch node — the app NEVER opens it */
  ciphered_otp: string;
  /** full mobile (the dispatch node's WhatsApp payload — display uses the hint) */
  mobile: string;
  /** masked mobile for the UI */
  mobile_hint: string;
  /** seconds until the code expires */
  expires_in: number;
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
  /** the enrollment's stage (this blackbox has no customer ids to return) */
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
  generateOtp(enrollmentId: string): Promise<GenerateOtpResponse>;
  verifyEnrollmentOtp(enrollmentId: string, otpCode: string): Promise<StageResponse>;
  recordConsent(enrollmentId: string, consentVersion: string): Promise<StageResponse>;
  submitEnrollmentFace(enrollmentId: string, embeddingEnc: string): Promise<SubmitFaceResponse>;
  getEnrollmentStatusByUsername(username: string): Promise<EnrollmentStatusResponse>;
  verifyFace(username: string, embeddingEnc: string): Promise<VerifyResponse>;
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
        username: req.username,
        password: req.password,
        mobile: req.mobile,
      }),
    generateOtp: (enrollmentId) =>
      request(
        'POST',
        `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/otp/generate`,
      ),
    verifyEnrollmentOtp: (enrollmentId, otpCode) =>
      // the typed code crosses SEALED (enc1:) — the backend refuses cleartext
      request('POST', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/otp`, {
        otp_code_enc: seal(otpCode),
      }),
    recordConsent: (enrollmentId, consentVersion) =>
      request('POST', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/consent`, {
        consent_version: consentVersion,
      }),
    submitEnrollmentFace: (enrollmentId, embeddingEnc) =>
      request('POST', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/face`, {
        embedding_enc: embeddingEnc,
      }),
    getEnrollmentStatusByUsername: (username) =>
      request(
        'GET',
        `/api/v1/enrollments/by-username/${encodeURIComponent(username)}/status`,
      ),
    verifyFace: (username, embeddingEnc) =>
      request('POST', '/api/v1/verifications', {
        username,
        embedding_enc: embeddingEnc,
      }),
  };
}

/** True only when the backend explicitly reports an enrolled record. */
export function isEnrolled(status: EnrollmentStatusResponse): boolean {
  return status.enrolled === true;
}
