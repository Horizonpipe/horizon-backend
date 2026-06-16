import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  nextDb3DuplicateReference,
  stripDb3ReferenceSuffix,
  isDb3DuplicateExcludeDecision,
  isDb3DuplicateIncludeDecision,
  rowHasJobsiteDuplicateFlag
} = require('../lib/db3-jobsite-duplicate.js');

assert.equal(stripDb3ReferenceSuffix('S-118-S-119#2'), 'S-118-S-119');
assert.equal(stripDb3ReferenceSuffix('S-118-S-119'), 'S-118-S-119');

const used = new Set(['s-118-s-119', 's-118-s-119#2']);
assert.equal(nextDb3DuplicateReference('S-118-S-119', used), 'S-118-S-119#3');
assert.equal(nextDb3DuplicateReference('S-200-S-201', used), 'S-200-S-201');

assert.equal(isDb3DuplicateExcludeDecision({ duplicateDecision: 'exclude' }), true);
assert.equal(isDb3DuplicateExcludeDecision({}), true);
assert.equal(isDb3DuplicateIncludeDecision({ duplicateDecision: 'include' }), true);
assert.equal(rowHasJobsiteDuplicateFlag({ placedDuplicate: true }), true);

console.log('db3-jobsite-duplicate.test.mjs: ok');
