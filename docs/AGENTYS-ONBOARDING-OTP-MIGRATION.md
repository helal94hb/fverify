# Onboarding OTP → fverify — migration card for the Agentys team

**The rule (owner, 2026-09-05): the banking BFF knows NOTHING about OTPs.**
fverify mints and verifies every OTP, end to end. Agentys carries the sealed
code to fverify and the boolean verdict back. The BFF's old enrol-OTP stub
(`/onboarding/otp/send`, `/otp/verify`, the `otp_code` branch of
`/enrollments/{id}/step`) is RETIRED once the graph below is live.

This reuses the exact surface already shipped for the face flow
(`AGENTYS-FACE-WORKFLOWS-SPEC.md` §1 stages 2–3) — no new fverify endpoints.

## The rewired onboarding graph (OTP stages only)

**Stage O1 — create the identity record (fverify), right after the START form.**
The START form already collects `{username, password, mobile}`.
```
POST {FVERIFY}/api/v1/enrollments
{ "username": "...", "password": "...", "mobile": "..." }
→ 201 { "enrollment_id", "status": "awaiting_otp", "mobile_hint" }
```
Idempotent per username: a restarted sign-up returns the SAME record — safe to
call on resume-after-abandon. Keep `enrollment_id` in the run state; it is the
OTP key for every later call. (No customer ids anywhere — the
username ↔ customer_id linkage is written later through the banking BFF's
linkage path, exactly as today.)

**Stage O2 — send the code (dispatch node, RAM only).**
```
POST {FVERIFY}/api/v1/enrollments/{enrollment_id}/otp/generate
→ 200 { "ciphered_otp": "aes256gcm:...", "mobile": "...", "mobile_hint", "expires_in": 600 }
```
A Code Execution Node: decrypts `ciphered_otp` with `OTP_DECRYPT_KEY` from the
secrets registry (AES-256-GCM, key shared with fverify), posts the code to the
WhatsApp API for `mobile`, and returns ONLY `{"status": "dispatched"}` to the
run state. The plaintext code must never enter the run state — that is the
whole point of the export token. Resend = call generate again; inside the
cooldown the server answers 429 `otp-resend-cooldown` — surface the wait, do
not retry-loop.

**Stage O3 — collect + verify (the verdict is fverify's).**
The app collects the 6 digits and seals them with fverify's public key
(`enc1:`, kid `fv-dev1`) — the mobile already does exactly this. The graph
resumes with `otp_code_enc` and a node calls:
```
POST {FVERIFY}/api/v1/enrollments/{enrollment_id}/otp
{ "otp_code_enc": "enc1:..." }
→ 200 { "status": "awaiting_consent" }   = VERIFIED → resume { otp_verified: "true" }
```
fverify opens the envelope (its own private key), compares, and answers. The
node must NOT attempt to decrypt — it transports the envelope untouched.

## Error map (all RFC 7807, titles are diagnostic)

| status | type | meaning for the graph |
|---|---|---|
| 422 | `invalid-otp-format` | the payload wasn't an `enc1:` envelope — app/integration bug, not a user error |
| 422 | `invalid-otp` | wrong/expired code — designed user retry (single-use, 5 attempts, TTL 600s) |
| 429 | `otp-resend-cooldown` | a code was just sent — wait the indicated seconds |
| 409 | `invalid-stage` | the enrollment isn't at the OTP stage (already verified, or consent done) |

## Keys

- `fv-dev1` public half ships in the app (seals the typed code); the private
  half lives ONLY in fverify's config.
- `OTP_DECRYPT_KEY` (AES-256-GCM export key) lives in fverify's config AND the
  Agentys secrets registry — nowhere else. Both are dev placeholders; rotate at
  first real deployment.

## After cutover (ours, not yours)

Once this graph is live, the banking side deletes the stub OTP code
(`send_enrol_otp` / `verify_enrol_otp` / the `otp_code` step branch) so the
rule holds in code, not just on paper. Until then the stub stays as the demo
fallback lane — unadvertised, and the app no longer calls it.
