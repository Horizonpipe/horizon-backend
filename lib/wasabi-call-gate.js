'use strict';

/**
 * Process-wide limit on live Wasabi HTTP calls.
 * Presigned URL signing does not use this gate (it never talks to Wasabi).
 * Extra calls wait briefly, then fail with 503 so nginx does not sit until it returns 502.
 */

class WasabiBusyError extends Error {
  constructor(retryAfterSec = 2) {
    super('Storage is busy. Retry shortly.');
    this.name = 'WasabiBusyError';
    this.code = 'WASABI_BUSY';
    this.retryAfterSec = retryAfterSec;
    this.statusCode = 503;
  }
}

function clampInt(name, fallback, min, max) {
  const raw = Number(process.env[name]);
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
}

const maxConcurrent = clampInt('WASABI_CALL_GATE_MAX', 12, 2, 64);
const maxWaitMs = clampInt('WASABI_CALL_GATE_WAIT_MS', 6000, 200, 30000);

let active = 0;
/** @type {{ resolve: (release: () => void) => void, reject: (err: Error) => void, timer: NodeJS.Timeout }[]} */
const waiters = [];

function releaseSlot() {
  active = Math.max(0, active - 1);
  const next = waiters.shift();
  if (!next) return;
  clearTimeout(next.timer);
  active += 1;
  next.resolve(makeRelease());
}

function makeRelease() {
  let released = false;
  return function release() {
    if (released) return;
    released = true;
    releaseSlot();
  };
}

function acquireWasabiSlot() {
  if (active < maxConcurrent) {
    active += 1;
    return Promise.resolve(makeRelease());
  }
  return new Promise((resolve, reject) => {
    const waiter = {
      resolve,
      reject,
      timer: setTimeout(() => {
        const idx = waiters.indexOf(waiter);
        if (idx >= 0) waiters.splice(idx, 1);
        reject(new WasabiBusyError(2));
      }, maxWaitMs)
    };
    waiters.push(waiter);
  });
}

async function withWasabiSlot(fn) {
  const release = await acquireWasabiSlot();
  try {
    return await fn();
  } finally {
    release();
  }
}

module.exports = {
  withWasabiSlot,
  WasabiBusyError
};
