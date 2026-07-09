import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  isTenantPortalClientId,
  isHiddenPortalTreeRelPath,
  filterHiddenPortalTreeForTenantClient
} = require('../lib/portal-hidden-tree-paths.js');

assert.equal(isTenantPortalClientId('tenant-acme'), true);
assert.equal(isTenantPortalClientId('portal-users'), false);

assert.equal(isHiddenPortalTreeRelPath('videos'), true);
assert.equal(isHiddenPortalTreeRelPath('videos/run1.mp4'), true);
assert.equal(isHiddenPortalTreeRelPath('db3'), true);
assert.equal(isHiddenPortalTreeRelPath('pdf'), true);
assert.equal(isHiddenPortalTreeRelPath('photos'), true);
assert.equal(isHiddenPortalTreeRelPath('system-state'), true);
assert.equal(isHiddenPortalTreeRelPath('My Project/videos'), false);
assert.equal(isHiddenPortalTreeRelPath('Jobsite A/report.pdf'), false);

const sample = {
  folders: [
    { path: 'db3', parentPath: '', name: 'db3' },
    { path: 'pdf', parentPath: '', name: 'pdf' },
    { path: 'Client A', parentPath: '', name: 'Client A' }
  ],
  files: [
    { path: 'videos/old.mp4', parentPath: 'videos', name: 'old.mp4' },
    { path: 'Client A/scan.pdf', parentPath: 'Client A', name: 'scan.pdf' }
  ]
};

const baseUnchanged = filterHiddenPortalTreeForTenantClient(sample, 'portal-users');
assert.equal(baseUnchanged.folders.length, 3);
assert.equal(baseUnchanged.files.length, 2);

const tenantFiltered = filterHiddenPortalTreeForTenantClient(sample, 'tenant-acme');
assert.deepEqual(
  tenantFiltered.folders.map((f) => f.path),
  ['Client A']
);
assert.deepEqual(
  tenantFiltered.files.map((f) => f.path),
  ['Client A/scan.pdf']
);

console.log('portal-hidden-tree-paths.test.mjs: ok');
