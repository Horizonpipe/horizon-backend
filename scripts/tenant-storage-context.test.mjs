import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  fullJobPrefix,
  fullObjectKey,
  parseJobFromPrefixedObjectKey,
  isPortalClientsObjectKey,
  assertKeyWithinTenantRoot,
  assertTenantPortalScope,
  tenantSlugFromRoot
} = require('../lib/tenant-storage-context.js');

const ROOT = 'tenants/acme-plumbing/';

assert.equal(fullJobPrefix('', 'horizon-pipe', '3'), 'clients/horizon-pipe/jobs/3/');
assert.equal(
  fullJobPrefix(ROOT, 'tenant-acme-plumbing', '1'),
  'tenants/acme-plumbing/clients/tenant-acme-plumbing/jobs/1/'
);

assert.equal(
  fullObjectKey(ROOT, 'tenant-acme-plumbing', '1', 'pdf', 'doc.pdf'),
  'tenants/acme-plumbing/clients/tenant-acme-plumbing/jobs/1/pdf/doc.pdf'
);

const legacyKey = 'clients/horizon-pipe/jobs/3/videos/a.mp4';
const prefixedKey = 'tenants/acme-plumbing/clients/tenant-acme-plumbing/jobs/1/pdf/doc.pdf';

assert.deepEqual(parseJobFromPrefixedObjectKey(legacyKey), {
  clientId: 'horizon-pipe',
  jobId: '3'
});
assert.deepEqual(parseJobFromPrefixedObjectKey(prefixedKey), {
  clientId: 'tenant-acme-plumbing',
  jobId: '1'
});

assert.equal(isPortalClientsObjectKey(legacyKey), true);
assert.equal(isPortalClientsObjectKey(prefixedKey), true);
assert.equal(isPortalClientsObjectKey('app-data/foo'), false);

assert.doesNotThrow(() => assertKeyWithinTenantRoot(prefixedKey, ROOT));
assert.throws(() => assertKeyWithinTenantRoot(legacyKey, ROOT));
assert.throws(() => assertKeyWithinTenantRoot(`${ROOT}clients/x/jobs/1/../../../etc`, ROOT));
assert.throws(() =>
  assertKeyWithinTenantRoot('tenants/other-tenant/clients/x/jobs/1/pdf/a.pdf', ROOT)
);
assert.doesNotThrow(() => assertKeyWithinTenantRoot(legacyKey, ''));

assert.doesNotThrow(() =>
  assertTenantPortalScope(
    { wasabiRootPrefix: ROOT, portalClientId: 'tenant-acme-plumbing', portalJobId: '1' },
    'tenant-acme-plumbing',
    '1'
  )
);
assert.throws(() =>
  assertTenantPortalScope(
    { wasabiRootPrefix: ROOT, portalClientId: 'tenant-acme-plumbing', portalJobId: '1' },
    'other-client',
    '1'
  )
);
assert.doesNotThrow(() => assertTenantPortalScope({ wasabiRootPrefix: '' }, 'any', '2'));

assert.equal(tenantSlugFromRoot(ROOT), 'acme-plumbing');

console.log('tenant-storage-context.test.mjs: ok');
