# Face-Verify — Integration Card (for Agentys only)

**Public base URL (dev, via Tailscale Funnel):**
`https://desktop-jnpu3pf.taila9e3e5.ts.net`

All routes are under `/api/v1`. Errors are RFC 7807 `application/problem+json`
(client-safe titles only — never internals).

> **THIS SERVICE IS A BLACKBOX IDENTITY PROVIDER.** It knows ONLY user
> identity — username, credential (password), face embedding, OTP. It has NO
> customer ids, NO banking data, NO T24 knowledge. The username ↔ customer_id
> linkage lives in the mobile DB (`identity_links`) and is written THROUGH
> AGENTYS — never through this service. (Owner ruling, 2026-08-31.)
>
> Caller rules: this surface is server-to-server for Agentys nodes only; face
> IMAGES never cross it (only sealed embedding vectors, `enc1:` RSA-OAEP, kid
> `fv-dev1`); unknown identities are INDISTINGUISHABLE from mismatches by design.

## Registration (staged: identity → OTP → consent → face)

### POST /api/v1/enrollments — register + send the OTP
```json
REQ  {"username": "face.user", "password": "••••••••", "mobile": "01000000000"}
RESP 201 {"enrollment_id": "<id>", "status": "awaiting_otp", "mobile_hint": "*** *** 000"}
```
Idempotent per username; resend while awaiting the OTP respects the cooldown
(429 `otp-resend-cooldown`).

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

### GET /api/v1/enrollments/by-username/{username}/status
```json
RESP 200 {"enrolled": true|false, "enrolled_at": "<iso8601>"|null, "status": "<stage>"|null}
```

### POST /api/v1/verifications — the match verdict (server-side, always)
```json
REQ  {"username": "face.user", "embedding_enc": "enc1:<sealed fresh capture>"}
RESP 200 {"verdict": "verified"|"rejected", "score": 0.0-1.0, "threshold": 0.8}
```
- Owner rulings: threshold **0.80**, retries capped at **3** failed attempts
  per username per 10 minutes → designed 429 `verification-locked`.
- An unknown username returns the SAME 200 + `rejected` shape as a real
  mismatch (no oracle).

## GET /api/v1/audit/recent?limit=50
Ops proof surface — outcomes only (created / verified / rejected / locked /
otp outcomes), timestamps, **username**. No embeddings, no customer ids,
nothing outside identity.
