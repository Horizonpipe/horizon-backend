'use strict';

const { parentPort } = require('worker_threads');
const { parseDb3 } = require('./db3-parse-core');

parentPort.on('message', async (msg) => {
  try {
    const buffer = Buffer.isBuffer(msg?.buffer) ? msg.buffer : Buffer.from(msg?.buffer || []);
    const metaRaw = msg?.metaBuffer;
    const metaBuffer = metaRaw && (Buffer.isBuffer(metaRaw) ? metaRaw : Buffer.from(metaRaw)).length
      ? (Buffer.isBuffer(metaRaw) ? metaRaw : Buffer.from(metaRaw))
      : null;
    const rows = await parseDb3(buffer, metaBuffer);
    parentPort.postMessage({ ok: true, rows: Array.isArray(rows) ? rows : [] });
  } catch (error) {
    parentPort.postMessage({
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    });
  }
});
