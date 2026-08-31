/**
 * Central config — the ONLY module that names the backend this app talks to.
 *
 * Standalone posture (owner ruling 2026-08-29): this base URL points at the
 * app's OWN small backend (face-verify/backend), never the digital-banking
 * BFF. No env var, endpoint, or tenant detail of the banking platform may be
 * referenced here.
 */

/**
 * Dev default for the on-device run: the emulator reaches the HOST's
 * standalone backend (127.0.0.1:8400 on the workstation) through the Android
 * emulator's host alias 10.0.2.2. Production wiring lands with deployment
 * config — there is intentionally no other environment mechanism in the
 * skeleton.
 */
export const API_BASE_URL = 'http://10.0.2.2:8400';

/**
 * Version of the consent copy the customer accepts. Sent to the backend with
 * every enrollment so consent records are versioned (design doc §3/§4).
 * Bump it whenever the copy in WelcomeConsentScreen changes.
 */
export const CONSENT_VERSION = '1.0';
