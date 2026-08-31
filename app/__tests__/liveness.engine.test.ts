/**
 * Liveness engine — pass path, timeout window, retry design, randomization,
 * and no-signal-no-pass. The engine is pure: a manual scheduler drives time
 * and a seeded RNG drives shuffle order, so nothing here is flaky.
 */

import {
  ALL_CHALLENGES,
  LivenessEngine,
  shuffleChallenges,
  type Challenge,
  type LivenessEvent,
  type LivenessSignal,
  type SignalDetector,
} from '../src/liveness/engine';

/** Manual timer queue — tests decide exactly when windows close. */
function createManualScheduler() {
  const pending: Array<{ fn: () => void; cancelled: boolean }> = [];
  const schedule = (fn: () => void, _ms: number) => {
    const entry = { fn, cancelled: false };
    pending.push(entry);
    return () => {
      entry.cancelled = true;
    };
  };
  /** Fire every still-live timer (cancelled ones stay dead). */
  const fireAll = () => {
    for (const entry of pending.splice(0)) {
      if (!entry.cancelled) entry.fn();
    }
  };
  return { schedule, fireAll, pendingCount: () => pending.filter((p) => !p.cancelled).length };
};

/** Seeded RNG so shuffle order is deterministic per test. */
function seededRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

/** Injected detector fake — captures the engine's emit callback on start. */
class FakeDetector implements SignalDetector {
  emit: ((signal: LivenessSignal) => void) | null = null;
  startCount = 0;
  stopCount = 0;
  start(emit: (signal: LivenessSignal) => void): void {
    this.emit = emit;
    this.startCount += 1;
  }
  stop(): void {
    this.stopCount += 1;
    this.emit = null;
  }
  signal(s: LivenessSignal): void {
    this.emit?.(s);
  }
}

function makeEngine(
  opts: {
    rng?: () => number;
    detector?: SignalDetector;
    maxAttempts?: number;
    onEvent?: (e: LivenessEvent) => void;
  } = {},
) {
  const scheduler = createManualScheduler();
  const engine = new LivenessEngine({
    schedule: scheduler.schedule,
    perChallengeTimeoutMs: 5000,
    rng: opts.rng ?? seededRng(1),
    ...(opts.detector ? { detector: opts.detector } : {}),
    ...(opts.maxAttempts !== undefined ? { maxAttempts: opts.maxAttempts } : {}),
    ...(opts.onEvent ? { onEvent: opts.onEvent } : {}),
  });
  return { engine, scheduler };
}

/** Drive the engine through whatever order it shuffled, via the detector. */
function passCurrentChallenge(engine: LivenessEngine, detector: FakeDetector): void {
  const current = engine.getSnapshot().currentChallenge;
  expect(current).not.toBeNull();
  detector.signal(current as Challenge);
}

describe('LivenessEngine — pass path', () => {
  it('passes the run only when every challenge is answered in order', () => {
    const detector = new FakeDetector();
    const events: LivenessEvent[] = [];
    const { engine } = makeEngine({ detector, onEvent: (e) => events.push(e) });

    engine.start();
    expect(engine.getSnapshot().state).toBe('active');
    expect(engine.getSnapshot().total).toBe(ALL_CHALLENGES.length);
    expect(detector.startCount).toBe(1);

    for (let i = 0; i < ALL_CHALLENGES.length; i++) {
      passCurrentChallenge(engine, detector);
    }

    const snap = engine.getSnapshot();
    expect(snap.state).toBe('passed');
    expect(snap.passedCount).toBe(ALL_CHALLENGES.length);
    expect(events.filter((e) => e.type === 'challenge')).toHaveLength(ALL_CHALLENGES.length);
    expect(events.filter((e) => e.type === 'challenge-passed')).toHaveLength(
      ALL_CHALLENGES.length,
    );
    expect(events.at(-1)).toEqual({ type: 'run-passed', attempt: 1 });
    // The detector is released once the run completes.
    expect(detector.stopCount).toBe(1);
  });

  it('issues one challenge at a time with progress', () => {
    const detector = new FakeDetector();
    const { engine } = makeEngine({ detector });
    engine.start();

    expect(engine.getSnapshot().passedCount).toBe(0);
    expect(engine.getSnapshot().currentChallenge).not.toBeNull();
    passCurrentChallenge(engine, detector);
    expect(engine.getSnapshot().passedCount).toBe(1);
    expect(engine.getSnapshot().state).toBe('active');
  });
});

describe('LivenessEngine — timeout window and retry design', () => {
  it('times out a challenge with no signal inside the window', () => {
    const events: LivenessEvent[] = [];
    const { engine, scheduler } = makeEngine({ onEvent: (e) => events.push(e) });
    engine.start();

    scheduler.fireAll(); // let the window close with no signal

    expect(engine.getSnapshot().state).toBe('timeout');
    const timeout = events.find((e) => e.type === 'run-timeout');
    expect(timeout).toMatchObject({ attempt: 1 });
  });

  it('a signal arriving after the window closed does NOT pass the challenge', () => {
    const { engine, scheduler } = makeEngine();
    engine.start();
    const challenge = engine.getSnapshot().currentChallenge as Challenge;

    scheduler.fireAll(); // window closes
    engine.handleSignal(challenge); // too late

    expect(engine.getSnapshot().state).toBe('timeout');
    expect(engine.getSnapshot().passedCount).toBe(0);
  });

  it('passing the current challenge cancels its timeout window', () => {
    const { engine, scheduler } = makeEngine();
    engine.start();
    const challenge = engine.getSnapshot().currentChallenge as Challenge;
    engine.handleSignal(challenge);

    // Exactly one live timer: the NEXT challenge's window. The passed
    // challenge's timer was cancelled, not left to fire later.
    expect(scheduler.pendingCount()).toBe(1);
    expect(engine.getSnapshot().state).toBe('active');
    expect(engine.getSnapshot().passedCount).toBe(1);

    // Finish the run, then nothing is pending — nothing can fire late.
    const order = engine.getSnapshot().order;
    for (const remaining of order.slice(1)) engine.handleSignal(remaining);
    expect(engine.getSnapshot().state).toBe('passed');
    expect(scheduler.pendingCount()).toBe(0);
    scheduler.fireAll();
    expect(engine.getSnapshot().state).toBe('passed');
  });

  it('retry reshuffles and restarts, and locks after maxAttempts', () => {
    const events: LivenessEvent[] = [];
    const { engine, scheduler } = makeEngine({ maxAttempts: 2, onEvent: (e) => events.push(e) });
    engine.start();

    // Attempt 1 times out → retry → attempt 2 times out → retry → exhausted.
    scheduler.fireAll();
    expect(engine.getSnapshot().state).toBe('timeout');
    engine.retry();
    expect(engine.getSnapshot().state).toBe('active');
    expect(engine.getSnapshot().attempt).toBe(2);

    scheduler.fireAll();
    engine.retry();
    expect(engine.getSnapshot().state).toBe('exhausted');
    expect(events.at(-1)).toEqual({ type: 'exhausted', attempts: 2 });

    // Exhausted is terminal for this engine — retry does not revive it.
    engine.retry();
    expect(engine.getSnapshot().state).toBe('exhausted');
  });
});

describe('LivenessEngine — randomization', () => {
  it('shuffle keeps every challenge exactly once (a permutation)', () => {
    for (let seed = 1; seed <= 20; seed++) {
      const order = shuffleChallenges(ALL_CHALLENGES, seededRng(seed));
      expect([...order].sort()).toEqual([...ALL_CHALLENGES].sort());
    }
  });

  it('different runs produce different challenge orders', () => {
    const orders = new Set<string>();
    for (let seed = 1; seed <= 50; seed++) {
      orders.add(shuffleChallenges(ALL_CHALLENGES, seededRng(seed)).join(','));
    }
    // With 3 challenges there are 6 permutations; 50 seeds must hit more than one.
    expect(orders.size).toBeGreaterThan(1);
  });

  it('a retry gets a freshly shuffled run (order re-drawn per run)', () => {
    const { engine, scheduler } = makeEngine({ rng: seededRng(7) });
    engine.start();
    const firstOrder = engine.getSnapshot().order;
    scheduler.fireAll();
    engine.retry();
    const secondOrder = engine.getSnapshot().order;
    expect(firstOrder).toHaveLength(secondOrder.length);
    // Both are permutations; the engine re-shuffles on every run (the RNG
    // stream advances, so a different draw is expected — but the guarantee we
    // pin is that retry issues a NEW order array from a fresh shuffle).
    expect(secondOrder).not.toBe(firstOrder);
    expect([...secondOrder].sort()).toEqual([...ALL_CHALLENGES].sort());
  });
});

describe('LivenessEngine — no-signal-no-pass', () => {
  it('a wrong signal never advances the run', () => {
    const { engine } = makeEngine();
    engine.start();
    const required = engine.getSnapshot().currentChallenge as Challenge;
    const wrong = ALL_CHALLENGES.find((c) => c !== required)!;

    engine.handleSignal(wrong);
    expect(engine.getSnapshot().passedCount).toBe(0);
    expect(engine.getSnapshot().currentChallenge).toBe(required);

    engine.handleSignal(required);
    expect(engine.getSnapshot().passedCount).toBe(1);
  });

  it('signals outside an active run are dropped', () => {
    const { engine } = makeEngine();
    engine.handleSignal('blink'); // idle — nothing listening
    expect(engine.getSnapshot().state).toBe('idle');
  });
});
