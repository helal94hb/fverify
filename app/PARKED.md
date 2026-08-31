# PARKED — channel-side reference code, not a shipped app (2026-08-31)

Owner ruling: **fverify is backend-only — it has NO frontend.** This directory
was built under an earlier misreading ("a standalone customer app") and is
parked, NOT deleted, because it is tested, working reference code for the
face-capture UI that belongs in a CHANNEL (the banking mobile app), driven by
an Agentys playbook — and moving it there is a separate, explicit decision
(the "future link to banking" the owner reserved).

What lives here and is directly reusable by the channel-side capture screen:
- `src/liveness/engine.ts` — the randomized challenge engine (fully jest-tested)
- `src/screens/` — consent / identity / OTP / document / liveness / verdict screens
- `src/ml/` — the enc1 JS seal + the embedding extractor adapter + the on-disk
  MobileFaceNet model (`assets/models/mobilefacenet.tflite`)
- `src/api.ts` — the client shapes (would re-point at Agentys, not at fverify)

What does NOT ship: any build of this as its own app, any direct
app→fverify-backend call (a channel never talks to a system directly).
