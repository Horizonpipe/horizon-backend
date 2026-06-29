'use strict';

const assert = require('assert');
const {
  resolveModeFromHost,
  resolveDeploymentProfile,
  getPublicDeploymentConfig,
  deploymentMode
} = require('../lib/deployment-profile');
const { resolveStorageBackend } = require('../lib/portal-storage-backend');

process.env.HP_DEPLOYMENT_MODE = 'hybrid';
process.env.SAAS_WASABI_BUCKET = 'saaspipeshare';
process.env.WASABI_BUCKET = 'legacy-bucket';

assert.strictEqual(resolveModeFromHost('pipeshare.live'), 'non-saas');
assert.strictEqual(resolveModeFromHost('www.pipeshare.live'), 'non-saas');
assert.strictEqual(resolveModeFromHost('pipeshare.net'), 'saas');
assert.strictEqual(resolveModeFromHost('techpipe.pipeshare.net'), 'saas');
assert.strictEqual(resolveModeFromHost('localhost'), null);

const baseProfile = resolveDeploymentProfile({ requestHost: 'pipeshare.live' });
assert.strictEqual(baseProfile.mode, 'non-saas');
assert.strictEqual(baseProfile.modeDerivedFromHost, true);
assert.strictEqual(baseProfile.features.platformReleasePublish, true);
assert.strictEqual(baseProfile.features.tenantVirtualboxStorage, false);

const saasProfile = resolveDeploymentProfile({ requestHost: 'techpipe.pipeshare.net' });
assert.strictEqual(saasProfile.mode, 'saas');
assert.strictEqual(saasProfile.tenantSlugFromHost, 'techpipe');
assert.strictEqual(saasProfile.features.tenantVirtualboxStorage, true);

const baseStorage = resolveStorageBackend({ headers: { host: 'pipeshare.live' } });
assert.strictEqual(baseStorage.useSaasBucket, false);
assert.strictEqual(baseStorage.bucket, 'legacy-bucket');

const saasStorage = resolveStorageBackend({ headers: { host: 'techpipe.pipeshare.net' } });
assert.strictEqual(saasStorage.useSaasBucket, true);
assert.strictEqual(saasStorage.bucket, 'saaspipeshare');

const pub = getPublicDeploymentConfig({ requestHost: 'pipeshare.net' });
assert.strictEqual(pub.mode, 'saas');
assert.strictEqual(pub.isSaasPlatform, true);

console.log('hybrid deployment-profile smoke OK');
