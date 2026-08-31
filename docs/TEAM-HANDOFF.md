# fverify — Team Handoff (2026-08-31)

**For:** the Agentys + mobile team · **Repo:** `helal94hb/fverify` · **Public dev URL:** `https://desktop-jnpu3pf.taila9e3e5.ts.net`

---

## 1. What this is

A **standalone face-verification app** for the Bank's customers: enroll once
(ID + guided liveness selfie), then prove "it's really me" anytime with a fresh
liveness capture. Entirely self-built — **no biometric vendor, no external
dependency for the customer**.

Two owner rulings govern everything:

1. **Full decoupling from digital banking.** The banking mobile app and its
   backend know *nothing* about this app — no shared code, no shared DB, no
   shared deployment. This repo is its own world (own app, own backend, own
   database).
2. **We build it ourselves.** No vendor SDK. Liveness and matching are our
   code, on our infrastructure.

## 2. Architecture at a glance

```
phone (our app)                          standalone backend (its own DB)
─────────────────                        ─────────────────────────────
camera capture                sealed     enrollments / verifications
guided liveness (blink/turn)  enc1:  →   encrypted embedding store
on-device face embedding      embedding  cosine match → VERDICT
(MobileFaceNet, on-device)    only       (server-side, never on device)
```

- **The only thing that crosses the wire is the embedding** — a vector of
  numbers, sealed with the platform's `enc1:` RSA-OAEP envelope. **No image
  ever leaves the phone or is stored anywhere** (discarded on-device after
  extraction).
- **The verdict is computed server-side.** A tampered phone cannot claim
  "matched" — same law as passwords: nothing is validated by the thing
  presenting it.
- The embedding model is **Qualcomm's MobileFaceNet** (Apache-2.0): 112×112
  face crop → 128-dim unit vector, cosine similarity, 99.48% on LFW. On disk
  at `app/assets/models/mobilefacenet.tflite`.

## 3. The two flows

**Enrollment (once):**
consent (explicit, versioned, *before* the camera) → national ID + mobile →
document capture → guided liveness selfie (randomized blink / turn-left /
turn-right challenges — a photo or a screen cannot blink on cue) → embedding
extracted on-device → sealed → backend stores it encrypted → `enrolled`.

**Verification (anytime):**
identify (national ID) → fresh liveness challenge loop → fresh embedding →
sealed → backend matches vs the enrolled record → `verified` / `rejected`
with a score. Five failures in 10 minutes → designed lockout. Every attempt
is audited (outcomes only — no embeddings in the audit trail).

## 4. Data rules (non-negotiable)

| Data | Where |
|---|---|
| Face images / ID photos / videos | **nowhere** — discarded on-device |
| Embeddings (numbers, never images) | this service's own DB, encrypted at rest |
| Consent + audit outcomes | same DB |
| Anything at a third party | **nothing — no vendor, no third party** |

## 5. The API (what Agentys calls)

Full contract with request/response shapes: **[INTEGRATION.md](../INTEGRATION.md)**.
Base URL today: `https://desktop-jnpu3pf.taila9e3e5.ts.net` (dev tunnel).

## 6. How Agentys connects (the honest shape)

Agentys **orchestrates and consumes verdicts — it never supplies a biometric.**
The capture physically cannot come from a workflow; it comes from the phone.
So the integration pattern is:

- **Gate by status:** a workflow that needs face-proofing checks
  `GET /enrollments/by-national-id/{id}/status` first — not enrolled → the
  customer is sent to enroll (the app), enrolled → proceed.
- **Trigger a verification:** the workflow prompts the customer to open the
  app and complete a verification; the app posts the sealed embedding; the
  workflow reads the outcome via the audit/verification response path.
- **Never** call these endpoints with a fabricated `embedding_enc` — unknown
  ids are indistinguishable from mismatches, and the lockout is real. The
  service is deliberately unfakeable.
- The `enc1:` envelope semantics are shared with the banking platform as a
  FORMAT only — this service's pair is `fv-dev1`, separate keys by design.

## 7. Status — what exists vs what's next

**Built and green (today):**
- Backend complete: 12 tests green (journeys, anti-enumeration, lockout,
  consent gate, sealed-only intake, encrypted-at-rest proof), ruff clean.
- App skeleton complete: 38 jest tests green (liveness engine, seal envelope,
  API client, flow state machine), typecheck + lint clean.
- Cross-language interop proof vendored: the app's JS seal opens on the
  python backend (a fixture test guards the contract permanently).

**In flight / next:**
- The native pipeline wiring (vision-camera + ML Kit face signals + the
  TFLite extractor behind the documented adapters) and the first debug APK.
- Then the device evidence run: enroll → verify → reject-a-photo, with
  screenshots.

**Honest limits (must travel with any demo):**
- Our liveness is challenge-response engineering, **not lab-certified
  anti-spoofing** (ISO 30107-3). If the Bank's regulator requires certified
  PAD, that is the one thing a vendor still sells.
- Before any production claim: publish FMR/FNMR from a labeled benchmark set
  + a bias audit. The thresholds are ours to prove.

## 8. Run it locally

```bash
# backend (http://127.0.0.1:8400)
cd backend && uv sync && uv run uvicorn app.main:app --port 8400

# tests
cd backend && uv run pytest -q          # 12 green
cd app && npm install && npx jest       # 38 green
```

## 9. Open decisions for the Architect (from the design doc)

1. Identity anchor at enrollment (PoC self-asserts national ID + mobile;
   production needs the real anchor — customer record / OTP-to-registered /
   in-branch).
2. Match threshold + retry/lockout policy (tuned from the benchmark, ratified).
3. Consent copy, retention window, delete-my-face path (PDPL class).
4. Play Integrity / App Attest hardening in phase 2 (recommended).
5. Any future link to the banking app is a NEW decision — none exists here.
