# Face-Verify — Integration Card (for Agentys / any orchestrator)

**Public base URL (dev, via Tailscale Funnel):**
`https://desktop-jnpu3pf.taila9e3e5.ts.net`

All routes are under `/api/v1`. Errors are RFC 7807 `application/problem+json`
(client-safe titles only — never internals).

> Hard rules for any caller: face IMAGES never cross this API (only sealed
> embedding vectors), embeddings arrive `enc1:`-sealed (RSA-OAEP-SHA-256, the
> platform's envelope format — this service's pair is kid `fv-dev1`), and an
> unknown identity is INDISTINGUISHABLE from a mismatch by design
> (anti-enumeration).

## The staged enrollment (owner rulings 2026-08-31)

national id → **T24 anchor** (customer id + REGISTERED mobile — the customer
never self-asserts the phone) → **fverify's own OTP** → consent → face.

### POST /api/v1/enrollments — open + send the OTP
```json
REQ  {"national_id": "12345678901234"}
RESP 201 {"enrollment_id": "<id>", "status": "awaiting_otp", "mobile_hint": "*** *** 000"}
```
404 `not-a-customer` when the national id is not a bank customer. Re-enrolling
while awaiting the OTP respects a resend cooldown (429 `otp-resend-cooldown`).

### POST /api/v1/enrollments/{enrollment_id}/otp — prove the code
```json
REQ  {"otp_code": "123456"}
RESP 200 {"status": "awaiting_consent"}
```
422 `invalid-otp` (single-use, TTL'd, 5 attempts). 409 `invalid-stage` out of order.

### POST /api/v1/enrollments/{enrollment_id}/consent
```json
REQ  {"consent_version": "1.0"}
RESP 200 {"status": "awaiting_face"}
```

### POST /api/v1/enrollments/{enrollment_id}/face — submit the face
```json
REQ  {"embedding_enc": "enc1:<sealed 128-dim embedding, compact wire encoding>"}
RESP 200 {"status": "enrolled", "enrolled_at": "<iso8601>"}
```
422 `invalid-embedding` for unsealed / image-like / malformed payloads;
409 `invalid-stage` before OTP + consent. The embedding is Fernet-encrypted
before it is stored.

## Status + verification

### GET /api/v1/enrollments/by-national-id/{national_id}/status
```json
RESP 200 {"enrolled": true|false, "enrolled_at": "<iso8601>"|null,
          "customer_id": "cust-000123"|null, "status": "<stage>"|null}
```

### POST /api/v1/verifications — the match verdict (server-side, always)
```json
REQ  {"national_id": "12345678901234", "embedding_enc": "enc1:<sealed fresh capture>"}
  OR {"customer_id": "cust-000123", "embedding_enc": "enc1:<...>"}   (exactly ONE key)
RESP 200 {"verdict": "verified"|"rejected", "score": 0.0-1.0, "threshold": 0.8}
```
- Owner rulings: threshold **0.80**, retries capped at **3** failed attempts
  per identity per 10 minutes → designed 429 `verification-locked`.
- An unknown identity returns the SAME 200 + `rejected` shape as a real
  mismatch (no oracle).

## GET /api/v1/audit/recent?limit=50
Ops proof surface — outcomes only (enrolled / verified / rejected / locked /
otp outcomes), timestamps, identity key. No embeddings anywhere in this service.
