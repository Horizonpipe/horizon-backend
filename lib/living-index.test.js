'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { openStore } = require('./living-index');

test('server index diff returns only rows newer than the cursor', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-server-index-'));
  const store = openStore(path.join(dir, 'living-index.sqlite'));
  const first = await store.pushOps('base', [
    { id: 'job:1', area: 'schedule', op: 'edit', name: 'Creek', revision: 1, client: 'c1', job: 'j1' }
  ]);
  assert.equal(first.applied.length, 1);
  const second = await store.pushOps('base', [
    { id: 'job:1', area: 'schedule', op: 'rename', name: 'Creek 2', revision: 2, client: 'c1', job: 'j1' },
    { id: 'job:1', area: 'schedule', op: 'edit', name: 'stale', revision: 1, client: 'c1', job: 'j1' }
  ]);
  assert.equal(second.applied.length, 1);
  assert.equal(second.skipped.length, 1);
  const diff = await store.diffSince('base', first.revision);
  assert.equal(diff.rows.length, 1);
  assert.equal(diff.rows[0].name, 'Creek 2');
  const tomb = await store.pushOps('base', [
    { id: 'job:1', area: 'schedule', op: 'delete', name: 'Creek 2', revision: second.revision, tombstone: 1 }
  ]);
  assert.equal(tomb.applied[0].tombstone, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});
