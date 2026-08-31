/**
 * Central config — the ONLY module that names the backend this app talks to.
 *
 * Standalone posture (owner ruling 2026-08-29): this base URL points at the
 * app's OWN small backend (face-verify/backend), never the digital-banking
 * BFF. No env var, endpoint, or tenant detail of the banking platform may be
 * referenced here.
 */

/**
 * Phase-A dev default. The standalone backend listens on 8400 in dev.
 * Production wiring lands with deployment config — there is intentionally no
 * other environment mechanism in the skeleton.
 */
export const API_BASE_URL = 'http://127.0.0.1:8400';

/**
 * Version of the consent copy the customer accepts. Sent to the backend with
 * every enrollment so consent records are versioned (design doc §3/§4).
 * Bump it whenever the copy in WelcomeConsentScreen changes.
 */
export const CONSENT_VERSION = '1.0';
