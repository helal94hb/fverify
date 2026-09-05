# Agentys Workflows — Face Verification (fverify) Requirements & Spec

**For:** the Agentys/playbook team · **Date:** 2026-08-31 · **Status:** ready to implement
**Companion contracts:** `face-verify/INTEGRATION.md` (the fverify endpoint shapes), `program/design/FACE-VERIFICATION-DESIGN.md` (the product design)

---

## 0. The architecture you are implementing into

```
CHANNELS (banking mobile app · OLB · any future face app)
   │  every request
   ▼
AGENTYS (the bank MW — these workflows)
   ├─► fverify (blackbox IdP) — username, credential, face, OTP. Nothing else.
   ├─► mobile DB identity_links — username ↔ customer_id (the linkage, YOU write it)
   └─► T24 — customer data by customer_id
```

**The law for these workflows:**

1. **fverify is a blackbox identity provider.** It knows ONLY user identity (username, password, face embedding, OTP). **Never send it a customer id, national id-as-customer-key, or any banking data** — it must never learn them.
2. **The linkage (username ↔ T24 customer_id) is YOURS** — your workflows resolve it and write it into the mobile DB's `identity_links`, through the banking BFF's onboarding/provisioning path (the D-DB-8 store; fverify has no part in it).
3. **No face image or template ever crosses Agentys** — images live device→(processing on device) and are discarded there. The only biometric on the wire is the **embedding, sealed** (`enc1:` RSA-OAEP-SHA-256, kid `fv-dev1`). Your run state must hold ciphertext only.
4. **The channel drives capture; you drive order; fverify answers.** A workflow never supplies a biometric.

## 1. Workflow A — Face Enrollment (`face_enrollment_v1`)

Orchestrates a first-time face enrollment for a customer of the Bank.

**Trigger inputs:** `{national_id, username, password, mobile}`

**Stage 1 — resolve the customer (T24):** national_id → customer_id (the core's GET; the same lookup the onboarding flows use). Not a customer → end with the designed refusal. The REGISTERED mobile from T24 is the OTP destination when available; the trigger's mobile is the fallback for the PoC.

**Stage 2 — register the identity (fverify):**
`POST /api/v1/enrollments` `{username, password, mobile}` → `{enrollment_id, status:"awaiting_otp", mobile_hint}`.
This call mints NO code. The code is minted by `POST /api/v1/enrollments/{id}/otp/generate` → `{ciphered_otp, mobile, mobile_hint, expires_in}` — `ciphered_otp` is AES-256-GCM under the shared export key (`FV_OTP_EXPORT_KEY` in the secrets registry). Your Code Execution Node decrypts it in RAM, dispatches via WhatsApp, and returns only a status to the run state — the plaintext code never lands in run state (see §4).

**Stage 3 — OTP proof (fverify):** the channel collects the code and SEALS it (`enc1:`, fverify's public key — the typed code never crosses you cleartext) →
`POST /api/v1/enrollments/{id}/otp` `{otp_code_enc}` → `{status:"awaiting_consent"}`.
422 `invalid-otp-format` if unsealed; 422 `invalid-otp` → the designed retry state (single-use, 5 attempts, resend cooldown 429 on a fresh generate).

**Stage 4 — consent (fverify):** the channel shows the consent copy (versioned) →
`POST /api/v1/enrollments/{id}/consent` `{consent_version}` → `{status:"awaiting_face"}`.

**Stage 5 — capture (channel):** document capture + guided liveness selfie on the device (see §3). The channel extracts the embedding ON-DEVICE and seals it (`enc1:`).

**Stage 6 — face submit (fverify):**
`POST /api/v1/enrollments/{id}/face` `{embedding_enc}` → `{status:"enrolled", enrolled_at}`.
409 `invalid-stage` if any earlier stage is incomplete; 422 `invalid-embedding` on any payload that isn't the sealed compact vector.

**Stage 7 — WRITE THE LINKAGE (yours, not fverify's):** on `enrolled`, write
`username ↔ customer_id` into the mobile DB `identity_links` via the banking
BFF's provisioning path (the same write the onboarding service performs at
enrolment — D-DB-8). From this moment, sign-in by username resolves the customer.

**Terminal state:** `completed`, outputs `{enrolled: true, username, customer_id, enrolled_at}`.

## 2. Workflow B — Face Verification (`face_verification_v1`)

Proves a person is physically present and matches an enrolled identity — usable as a standalone check or as the step-up authenticator inside another flow (transfer confirm, payee add).

**Trigger inputs:** `{username}` (+ optional `intent_ref` when embedded as a step-up).

**Stage 1 — enrolled check (fverify):**
`GET /api/v1/enrollments/by-username/{username}/status` → `enrolled?` Not enrolled → the designed "enroll first" state (offer Workflow A).

**Stage 2 — capture (channel):** fresh guided liveness challenge (randomized blink/turn sequence; a photo or screen cannot blink on cue). Channel extracts + seals the fresh embedding.

**Stage 3 — match (fverify):**
`POST /api/v1/verifications` `{username, embedding_enc}` → `{verdict, score, threshold}`.
- `verified` → the run completes (or the step-up token may be issued by the calling flow).
- `rejected` → the designed retry state; after **3** failures in 10 min fverify answers 429 `verification-locked` — map it to the designed lockout screen, not a generic error.

**Terminal state:** `completed` with `{verified, score, threshold}` or the designed failure state.

## 3. What the channel does (your screens)

The capture UI belongs to the channel (banking mobile app) and is driven by YOUR stage outputs. Tested reference code is parked at `face-verify/app/PARKED.md` (consent / identity / OTP / document / liveness / verdict screens, the randomized liveness engine, the on-device embedding extractor with MobileFaceNet `mobilefacenet.tflite`, and the JS `enc1:` seal). It is reference code, not a shipped app — lift what you need; the flow state comes from the workflow, not from the app.

## 4. The OTP dispatch seam (LANDED, 2026-09-02)

fverify mints and verifies every OTP itself (owner ruling — the banking BFF
knows NOTHING about OTPs). Delivery rides the 3-layer dispatch architecture the
team shipped: `POST /api/v1/enrollments/{id}/otp/generate` returns
`ciphered_otp` — the plaintext code AES-256-GCM-encrypted under the shared
export key (`FV_OTP_EXPORT_KEY` / `OTP_DECRYPT_KEY` in the Agentys secrets
registry). Your Code Execution Node decrypts it in RAM, fires the WhatsApp
dispatch, and returns only `{"status": "dispatched"}` to the run state. The
plaintext code never lands in Agentys' Postgres; the typed code crosses back
sealed (`enc1:`, fv-dev1) and fverify alone opens it.

The same two endpoints (generate + verify) are the target for the banking
SIGN-UP OTP too — see `AGENTYS-ONBOARDING-OTP-MIGRATION.md`.

## 5. Errors you must map (never invent new shapes)

From `INTEGRATION.md` — map each to its designed channel state:
`otp-resend-cooldown` (429) · `invalid-otp` (422) · `invalid-otp-format` (422) · `invalid-stage` (409) · `invalid-embedding` (422) · `verification-locked` (429) · RFC 7807 envelope throughout.

## 6. Hard rules checklist (the validator will test these)

- [ ] No customer id ever appears in an fverify call or in fverify's store.
- [ ] The linkage write (Stage A-7) happens in the mobile DB, never in fverify.
- [ ] No image/frame/selfie/document crosses any node or sits in run state.
- [ ] The embedding crosses sealed end-to-end; only fverify unseals (fv-dev1).
- [ ] Verdicts come from fverify only — the workflow never derives its own match.
- [ ] Lockout/cooldown problems map to designed screens, never generic errors.

## 7. Reference endpoints (today, dev)

Base: `https://desktop-jnpu3pf.taila9e3e5.ts.net` · the five routes + audit in `face-verify/INTEGRATION.md` (exact payload/response shapes — implement against that card, not from memory).

---

## Q&A (team round 1, 2026-09-02)

**Q1. Do we get the face embeddings from fverify or the mobile app?**
The embedding is PRODUCED on the device (the channel captures + seals it), but
it FLOWS through Agentys — never app→fverify directly. The face-submit node
forwards the sealed blob; fverify unseals. (§1 Stage 6 read as if fverify faced
the channel — corrected: channels never call systems.)

**Q2. Workflow A's trigger inputs come from the sign-up form, sent directly to
Agentys?**
Yes — the channel collects the form and triggers the workflow. Rule on top:
the `password` rides SEALED even in the trigger, and each payload seals to its
ULTIMATE VALIDATOR's public key — enrollment's password seals to fv-dev1 (it
ends at fverify); sign-in's password seals to dev1 (it ends at the validator
on the mobile DB).

**Q3. OTP: does fverify mint AND dispatch the SMS? Or does Agentys call a
separate dispatch service, wait for the app to collect the code, then send it
to fverify's /otp?**
fverify ALWAYS mints and ALWAYS validates — never leaves it. The target shape
is your second reading: fverify's dispatch seam calls the Agentys SMS workflow
(your build) → SMS goes out → the channel collects the code from the user →
your OTP-verify node calls fverify's /otp to validate. Until the SMS workflow
lands, fverify runs the dev stub (fixed code 123456).

**Q4. Is fverify an identity provider that replaces HID?**
For this platform: yes — credentials + face + OTP, with the linkage in the
mobile DB via your workflows. Whether it institutionally replaces the Bank's
HID estate is the Bank's decision; for our build, fverify IS the IdP and HID
becomes optional rather than load-bearing.
