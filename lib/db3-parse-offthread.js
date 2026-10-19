'use strict';

const path = require('path');
const { Worker } = require('worker_threads');

const PARSE_TIMEOUT_MS = Math.max(
  15000,
  Math.min(180000, Number(process.env.DB3_PARSE_TIMEOUT_MS || 90000))
);

/** One parse at a time in this process so sql.js cannot stall every request. */
let chain = Promise.resolve();

/**
 * Parse a WinCan DB3 off the HTTP event loop.
 * The caller's buffers are copied into the worker and left intact.
 * @param {Buffer} buffer
 * @param {Buffer | null} [metaBuffer]
 */
function parseDb3OffThread(buffer, metaBuffer = null) {
  const run = () => runOnce(buffer, metaBuffer);
  const next = chain.then(run, run);
  chain = next.then(
    () => {},
    () => {}
  );
  return next;
}

function runOnce(buffer, metaBuffer) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'db3-parse-worker.js'));
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate().catch(() => {});
      fn(value);
    };
    const timer = setTimeout(() => {
      finish(reject, new Error('DB3 parse timed out'));
    }, PARSE_TIMEOUT_MS);
    worker.once('message', (msg) => {
      if (msg && msg.ok) finish(resolve, Array.isArray(msg.rows) ? msg.rows : []);
      else finish(reject, new Error((msg && msg.error) || 'DB3 parse failed'));
    });
    worker.once('error', (err) => finish(reject, err));
    worker.once('exit', (code) => {
      if (!settled && code !== 0) finish(reject, new Error(`DB3 parse worker exited (${code})`));
    });
    worker.postMessage({
      buffer: Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || []),
      metaBuffer: metaBuffer && metaBuffer.length ? metaBuffer : null
    });
  });
}

module.exports = { parseDb3OffThread };
