/**
 * Active liveness challenge engine — PURE logic, no React, no native imports.
 *
 * Challenge-response is the replay control (design doc §5): a photo or a
 * screen cannot blink on cue, and every run RANDOMIZES the challenge order so
 * a recording cannot anticipate it. One challenge at a time; a challenge
 * passes only when its required signal arrives inside its time window;
 * all-pass lets the flow proceed; a timeout lands in a designed retry state
 * (bounded by maxAttempts, then 'exhausted' — fail closed, never a pass).
 *
 * Everything time- or chance-related is INJECTED so jest drives it fully:
 *   - `rng`      — Math.random in the app, a seeded function in tests.
 *   - `schedule` — setTimeout in the app, a manual timer queue in tests.
 *   - `detector` — the face-signal source. In the app this is the stub in
 *     LivenessChallengeScreen today and the ML Kit / vision-camera frame
 *     processor next iteration; in tests a fake that emits on demand.
 */

export type Challenge = 'blink' | 'turn-left' | 'turn-right';

/** The signal a detector reports — the challenge it believes the user just did. */
export type LivenessSignal = Challenge;

export const ALL_CHALLENGES: readonly Challenge[] = ['blink', 'turn-left', 'turn-right'];

/**
 * The injected detector interface. The engine owns WHEN it listens
 * (start/stop around a run); the detector owns HOW signals are observed.
 */
export interface SignalDetector {
  start(emit: (signal: LivenessSignal) => void): void;
  stop(): void;
}

export type LivenessState = 'idle' | 'active' | 'passed' | 'timeout' | 'exhausted';

export interface LivenessSnapshot {
  state: LivenessState;
  currentChallenge: Challenge | null;
  /** The shuffled order for the current run — never the same twice by design. */
  order: Challenge[];
  passedCount: number;
  total: number;
  attempt: number;
  maxAttempts: number;
}

export type LivenessEvent =
  | { type: 'challenge'; challenge: Challenge; index: number; total: number; attempt: number }
  | { type: 'challenge-passed'; challenge: Challenge; passedCount: number; total: number }
  | { type: 'run-passed'; attempt: number }
  | { type: 'run-timeout'; challenge: Challenge; attempt: number }
  | { type: 'exhausted'; attempts: number };

export type Scheduler = (fn: () => void, ms: number) => () => void;

export interface LivenessEngineOptions {
  detector?: SignalDetector;
  rng?: () => number;
  schedule?: Scheduler;
  perChallengeTimeoutMs?: number;
  maxAttempts?: number;
  challenges?: Challenge[];
  onEvent?: (event: LivenessEvent) => void;
}

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_ATTEMPTS = 3;

/** Fisher–Yates with an injected RNG — deterministic under a seeded test RNG. */
export function shuffleChallenges(challenges: readonly Challenge[], rng: () => number): Challenge[] {
  const out = [...challenges];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = out[i]!;
    out[i] = out[j]!;
    out[j] = tmp;
  }
  return out;
}

const defaultSchedule: Scheduler = (fn, ms) => {
  const timer = setTimeout(fn, ms);
  return () => clearTimeout(timer);
};

export class LivenessEngine {
  private state: LivenessState = 'idle';
  private order: Challenge[] = [];
  private index = 0;
  private attempt = 0;
  private cancelTimer: (() => void) | null = null;

  private readonly detector?: SignalDetector;
  private readonly rng: () => number;
  private readonly schedule: Scheduler;
  private readonly perChallengeTimeoutMs: number;
  private readonly maxAttempts: number;
  private readonly challenges: Challenge[];
  private readonly onEvent?: (event: LivenessEvent) => void;

  constructor(options: LivenessEngineOptions = {}) {
    this.detector = options.detector;
    this.rng = options.rng ?? Math.random;
    this.schedule = options.schedule ?? defaultSchedule;
    this.perChallengeTimeoutMs = options.perChallengeTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.challenges = [...(options.challenges ?? ALL_CHALLENGES)];
    this.onEvent = options.onEvent;
  }

  getSnapshot(): LivenessSnapshot {
    return {
      state: this.state,
      currentChallenge: this.state === 'active' ? (this.order[this.index] ?? null) : null,
      order: [...this.order],
      passedCount: this.state === 'passed' ? this.order.length : this.index,
      total: this.order.length,
      attempt: this.attempt,
      maxAttempts: this.maxAttempts,
    };
  }

  /** Begin attempt 1. No-op if a run is already active. */
  start(): void {
    if (this.state === 'active') return;
    this.attempt = 1;
    this.beginRun();
  }

  /**
   * The designed retry state: after a timeout the caller may retry, which
   * RE-SHUFFLES the order (a recording cannot reuse the previous sequence).
   * Beyond maxAttempts the engine locks into 'exhausted' — fail closed.
   */
  retry(): void {
    if (this.state !== 'timeout') return;
    if (this.attempt >= this.maxAttempts) {
      this.state = 'exhausted';
      this.emit({ type: 'exhausted', attempts: this.attempt });
      return;
    }
    this.attempt += 1;
    this.beginRun();
  }

  /**
   * Feed an observed signal. A challenge passes ONLY when the signal matches
   * the current required challenge while its window is open — a wrong signal
   * is ignored (never a pass), and a signal outside 'active' is dropped.
   */
  handleSignal(signal: LivenessSignal): void {
    if (this.state !== 'active') return;
    const required = this.order[this.index];
    if (signal !== required) return;

    this.clearTimer();
    this.index += 1;
    this.emit({
      type: 'challenge-passed',
      challenge: required!,
      passedCount: this.index,
      total: this.order.length,
    });

    if (this.index >= this.order.length) {
      this.state = 'passed';
      this.detector?.stop();
      this.emit({ type: 'run-passed', attempt: this.attempt });
      return;
    }
    this.issueChallenge();
  }

  /** Stop listening and cancel any open window. Idempotent. */
  dispose(): void {
    this.clearTimer();
    this.detector?.stop();
  }

  private beginRun(): void {
    this.order = shuffleChallenges(this.challenges, this.rng);
    this.index = 0;
    this.state = 'active';
    this.detector?.start((signal) => this.handleSignal(signal));
    this.issueChallenge();
  }

  private issueChallenge(): void {
    const challenge = this.order[this.index]!;
    this.clearTimer();
    this.cancelTimer = this.schedule(() => this.onTimeout(), this.perChallengeTimeoutMs);
    this.emit({
      type: 'challenge',
      challenge,
      index: this.index,
      total: this.order.length,
      attempt: this.attempt,
    });
  }

  private onTimeout(): void {
    if (this.state !== 'active') return;
    const challenge = this.order[this.index]!;
    this.state = 'timeout';
    this.detector?.stop();
    this.emit({ type: 'run-timeout', challenge, attempt: this.attempt });
  }

  private clearTimer(): void {
    this.cancelTimer?.();
    this.cancelTimer = null;
  }

  private emit(event: LivenessEvent): void {
    this.onEvent?.(event);
  }
}
