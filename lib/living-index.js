'use strict';

/**
 * One living index for the server. Isolated from portal file bytes.
 * File: <horizon-backend>/data/living-index.sqlite
 * A diff is the rows whose revision is newer than the caller's cursor.
 */
const fs = require('fs');
const path = require('path');

function loadSql() {
  return require('sql.js');
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rows (
  scope TEXT NOT NULL,
  id TEXT NOT NULL,
  area TEXT NOT NULL DEFAULT '',
  op TEXT NOT NULL DEFAULT 'edit',
  path TEXT NOT NULL DEFAULT '',
  parent TEXT NOT NULL DEFAULT '',
  client TEXT NOT NULL DEFAULT '',
  job TEXT NOT NULL DEFAULT '',
  byte_size INTEGER NOT NULL DEFAULT 0,
  content_hash TEXT NOT NULL DEFAULT '',
  etag TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT '',
  revision INTEGER NOT NULL DEFAULT 0,
  tombstone INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (scope, id)
);
CREATE INDEX IF NOT EXISTS rows_scope_revision ON rows(scope, revision);
`;

let sqlPromise = null;

function getSql() {
  if (!sqlPromise) {
    const initSqlJs = loadSql();
    sqlPromise = initSqlJs({
      locateFile: (file) => require.resolve(`sql.js/dist/${file}`)
    });
  }
  return sqlPromise;
}

function clip(value, max) {
  return String(value == null ? '' : value).slice(0, max);
}

function asRow(obj) {
  if (!obj) return null;
  let payload = {};
  try {
    payload = JSON.parse(String(obj.payload || '{}'));
  } catch {
    payload = {};
  }
  return {
    id: String(obj.id || ''),
    area: String(obj.area || ''),
    op: String(obj.op || 'edit'),
    path: String(obj.path || ''),
    parent: String(obj.parent || ''),
    client: String(obj.client || ''),
    job: String(obj.job || ''),
    byteSize: Number(obj.byte_size || 0) || 0,
    contentHash: String(obj.content_hash || ''),
    etag: String(obj.etag || ''),
    createdAt: String(obj.created_at || ''),
    updatedAt: String(obj.updated_at || ''),
    revision: Number(obj.revision || 0) || 0,
    tombstone: Number(obj.tombstone || 0) === 1 ? 1 : 0,
    name: String(obj.name || ''),
    payload
  };
}

/**
 * Tombstones beat a stale live copy. A newer revision still wins.
 * Identical content hash skips a byte transfer; the server index never stores bytes.
 */
function chooseWinner(existing, incoming) {
  if (!existing) return 'incoming';
  const existingRev = Number(existing.revision || 0);
  const incomingRev = Number(incoming.revision || 0);
  const existingDead = Number(existing.tombstone || 0) === 1;
  const incomingDead = Number(incoming.tombstone || 0) === 1;
  if (incomingDead && incomingRev >= existingRev) return 'incoming';
  if (existingDead && existingRev >= incomingRev) return 'existing';
  if (incomingRev > existingRev) return 'incoming';
  if (existingRev > incomingRev) return 'existing';
  if (incomingDead && !existingDead) return 'incoming';
  if (existingDead && !incomingDead) return 'existing';
  return 'existing';
}

function openStore(filePath) {
  const file = path.resolve(filePath);
  let chain = Promise.resolve();
  let db = null;

  function enqueue(task) {
    const run = chain.then(task, task);
    chain = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  async function ready() {
    if (db) return db;
    const SQL = await getSql();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    try {
      const buf = fs.readFileSync(file);
      db = new SQL.Database(new Uint8Array(buf));
    } catch {
      db = new SQL.Database();
    }
    db.run(SCHEMA);
    return db;
  }

  function persist(database) {
    const data = database.export();
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, Buffer.from(data));
    fs.renameSync(tmp, file);
  }

  function cursorKey(scope) {
    return `revision:${scope}`;
  }

  function readCursor(database, scope) {
    const stmt = database.prepare('SELECT value FROM meta WHERE key = ?');
    stmt.bind([cursorKey(scope)]);
    const value = stmt.step() ? Number(stmt.getAsObject().value || 0) || 0 : 0;
    stmt.free();
    return value;
  }

  function writeCursor(database, scope, revision) {
    database.run(
      'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
      [cursorKey(scope), String(revision)]
    );
  }

  function readRow(database, scope, id) {
    const stmt = database.prepare('SELECT * FROM rows WHERE scope = ? AND id = ?');
    stmt.bind([scope, id]);
    const row = stmt.step() ? asRow(stmt.getAsObject()) : null;
    stmt.free();
    return row;
  }

  return {
    filePath: file,
    chooseWinner,

    head(scope) {
      return enqueue(async () => {
        const database = await ready();
        return { revision: readCursor(database, scope) };
      });
    },

    diffSince(scope, since) {
      return enqueue(async () => {
        const database = await ready();
        const cursor = Math.max(0, Number(since || 0) || 0);
        const stmt = database.prepare(
          'SELECT * FROM rows WHERE scope = ? AND revision > ? ORDER BY revision ASC'
        );
        stmt.bind([scope, cursor]);
        const rows = [];
        while (stmt.step()) rows.push(asRow(stmt.getAsObject()));
        stmt.free();
        return { revision: readCursor(database, scope), since: cursor, rows };
      });
    },

    pushOps(scope, ops) {
      return enqueue(async () => {
        const database = await ready();
        const cleanScope = clip(scope, 160) || 'base';
        let cursor = readCursor(database, cleanScope);
        const applied = [];
        const skipped = [];
        const list = Array.isArray(ops) ? ops.slice(0, 500) : [];
        for (const raw of list) {
          const id = clip(raw?.id, 180);
          if (!id) continue;
          const payloadText = JSON.stringify(raw?.payload && typeof raw.payload === 'object' ? raw.payload : {});
          if (payloadText.length > 600000 || /data:|base64,/i.test(payloadText.slice(0, 80))) {
            skipped.push({ id, reason: 'payload' });
            continue;
          }
          const incoming = {
            id,
            area: clip(raw?.area, 40),
            op: clip(raw?.op || 'edit', 20),
            path: clip(raw?.path, 800),
            parent: clip(raw?.parent, 800),
            client: clip(raw?.client, 120),
            job: clip(raw?.job, 120),
            byteSize: Math.max(0, Number(raw?.byteSize || raw?.byte_size || 0) || 0),
            contentHash: clip(raw?.contentHash || raw?.content_hash, 128),
            etag: clip(raw?.etag, 180),
            createdAt: clip(raw?.createdAt || raw?.created_at, 40),
            revision: Math.max(0, Number(raw?.revision || 0) || 0),
            tombstone: Number(raw?.tombstone || 0) === 1 ? 1 : 0,
            name: clip(raw?.name, 240),
            payload: raw?.payload && typeof raw.payload === 'object' ? raw.payload : {}
          };
          const existing = readRow(database, cleanScope, id);
          if (chooseWinner(existing, incoming) === 'existing') {
            skipped.push({ id, reason: 'stale', row: existing });
            continue;
          }
          cursor += 1;
          const now = new Date().toISOString();
          database.run(
            `INSERT INTO rows (
              scope, id, area, op, path, parent, client, job, byte_size, content_hash, etag,
              created_at, updated_at, revision, tombstone, name, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope, id) DO UPDATE SET
              area = excluded.area,
              op = excluded.op,
              path = excluded.path,
              parent = excluded.parent,
              client = excluded.client,
              job = excluded.job,
              byte_size = excluded.byte_size,
              content_hash = excluded.content_hash,
              etag = excluded.etag,
              updated_at = excluded.updated_at,
              revision = excluded.revision,
              tombstone = excluded.tombstone,
              name = excluded.name,
              payload = excluded.payload`,
            [
              cleanScope,
              id,
              incoming.area,
              incoming.op,
              incoming.path,
              incoming.parent,
              incoming.client,
              incoming.job,
              incoming.byteSize,
              incoming.contentHash,
              incoming.etag,
              incoming.createdAt || existing?.createdAt || now,
              now,
              cursor,
              incoming.tombstone,
              incoming.name,
              payloadText
            ]
          );
          applied.push(readRow(database, cleanScope, id));
        }
        writeCursor(database, cleanScope, cursor);
        persist(database);
        return { revision: cursor, applied, skipped };
      });
    }
  };
}

const defaultFile = path.join(__dirname, '..', 'data', 'living-index.sqlite');
let singleton = null;

function store() {
  if (!singleton) singleton = openStore(defaultFile);
  return singleton;
}

module.exports = {
  openStore,
  chooseWinner,
  defaultFile,
  head: (scope) => store().head(scope),
  diffSince: (scope, since) => store().diffSince(scope, since),
  pushOps: (scope, ops) => store().pushOps(scope, ops)
};
