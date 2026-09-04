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

### POST /api/v1/enrollments — register the identity (record only)
```json
REQ  {"username": "face.user", "password": "••••••••", "mobile": "01000000000"}
RESP 201 {"enrollment_id": "<id>", "status": "awaiting_otp", "mobile_hint": "*** *** 000"}
```
Idempotent per username. **This call mints NO code** — OTP generation is the
dedicated generate endpoint below (OTP dispatch refactor, 2026-09-02).

### POST /api/v1/enrollments/{enrollment_id}/otp/generate — mint + export the OTP
```json
RESP 200 {"enrollment_id": "<id>", "ciphered_otp": "aes256gcm:<nonce|ct|tag>",
          "mobile": "01000000000", "mobile_hint": "*** *** 000", "expires_in": 600}
```
The 3-layer dispatch architecture: fverify OWNS the OTP (mint + verify);
`ciphered_otp` is the plaintext code AES-256-GCM-encrypted under the shared
export key (`FV_OTP_EXPORT_KEY` — fverify holds it, the Agentys secrets
registry holds it). The Agentys Code Execution Node decrypts it in RAM, fires
the WhatsApp dispatch to `mobile`, and returns only a status to the run state —
the plaintext code never lands in Agentys' Postgres. Resend within the cooldown
window → 429 `otp-resend-cooldown`. 409 `invalid-stage` once past
`awaiting_otp`.

### POST /api/v1/enrollments/{enrollment_id}/otp — prove the code
```json
REQ  {"otp_code_enc": "enc1:<the typed 6-digit code, RSA-OAEP-sealed, kid fv-dev1>"}
RESP 200 {"status": "awaiting_consent"}
```
The typed code ALWAYS crosses sealed — the app seals it with fverify's public
key so the orchestrator never carries it cleartext. An unsealed payload is a
designed 422 `invalid-otp-format`; a wrong/expired code is 422 `invalid-otp`
(single-use, TTL'd, 5 attempts). 409 `invalid-stage` out of order.

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
