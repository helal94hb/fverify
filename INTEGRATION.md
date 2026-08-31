# Face-Verify — Integration Card (for Agentys / any orchestrator)

**Public base URL (dev, via Tailscale Funnel):**
`https://desktop-jnpu3pf.taila9e3e5.ts.net`

All routes are under `/api/v1`. Errors are RFC 7807 `application/problem+json`
(client-safe titles only — never internals).

> Hard rules for any caller: face IMAGES never cross this API (only sealed
> embedding vectors), embeddings arrive `enc1:`-sealed (RSA-OAEP-SHA-256, the
> platform's envelope format — this service's pair is kid `fv-dev1`), and an
> unknown national_id is INDISTINGUISHABLE from a mismatch by design
> (anti-enumeration).

## POST /api/v1/enrollments — open an enrollment
```json
REQ  {"national_id": "12345678901234", "mobile": "01000000000", "consent_version": "1.0"}
RESP 201 {"enrollment_id": "<id>", "status": "awaiting_face"}
```
Consent is required before any face data is accepted. Re-enrolling the same
national id returns the existing open enrollment (idempotent).

## POST /api/v1/enrollments/{enrollment_id}/face — submit the face
```json
REQ  {"embedding_enc": "enc1:<sealed 128-dim embedding, compact wire encoding>"}
RESP 200 {"status": "enrolled", "enrolled_at": "<iso8601>"}
```
422 `urn:face-verify:problem:invalid-embedding` for unsealed / image-like /
malformed payloads. The embedding is Fernet-encrypted before it is stored.

## GET /api/v1/enrollments/by-national-id/{national_id}/status
```json
RESP 200 {"enrolled": true|false, "enrolled_at": "<iso8601>"|null}
```

## POST /api/v1/verifications — the match verdict (server-side, always)
```json
REQ  {"national_id": "12345678901234", "embedding_enc": "enc1:<sealed fresh capture>"}
RESP 200 {"verdict": "verified"|"rejected", "score": 0.0-1.0, "threshold": 0.6}
```
- 5 failed attempts per national_id per 10 minutes → designed 429
  `urn:face-verify:problem:verification-locked`.
- An unknown national_id returns the SAME 200 + `rejected` shape as a real
  mismatch (no oracle).

## GET /api/v1/audit/recent?limit=50
Ops proof surface — outcomes only (enrolled / verified / rejected / locked),
timestamps, national_id. No embeddings anywhere in this service.
