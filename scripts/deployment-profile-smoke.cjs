#!/usr/bin/env node
'use strict';

const assert = require('assert');
const {
  deploymentMode,
  resolveDeploymentProfile,
  getPublicDeploymentConfig
} = require('../lib/deployment-profile');
const { resolveStorageBackendForProcess } = require('../lib/portal-storage-backend');

process.env.HP_DEPLOYMENT_MODE = 'non-saas';
delete process.env.SAAS_WASABI_BUCKET;
const baseProfile = resolveDeploymentProfile({ requestHost: 'pipeshare.live' });
assert.strictEqual(baseProfile.mode, 'non-saas');
assert.strictEqual(baseProfile.isPrivateBase, true);
assert.strictEqual(baseProfile.features.platformReleasePublish, true);
assert.strictEqual(baseProfile.features.platformReleaseApply, false);

process.env.HP_DEPLOYMENT_MODE = 'saas';
process.env.SAAS_WASABI_BUCKET = 'saaspipeshare';
const saasProfile = resolveDeploymentProfile({ requestHost: 'techpipe.pipeshare.net' });
assert.strictEqual(saasProfile.mode, 'saas');
assert.strictEqual(saasProfile.tenantSlugFromHost, 'techpipe');
assert.strictEqual(saasProfile.features.tenantVirtualboxStorage, true);

const pub = getPublicDeploymentConfig({ requestHost: 'techpipe.pipeshare.net' });
assert.strictEqual(pub.isTenantWorkspaceHost, true);
assert.strictEqual(pub.tenantSlugFromHost, 'techpipe');

process.env.HP_DEPLOYMENT_MODE = 'non-saas';
const baseStorage = resolveStorageBackendForProcess();
assert.strictEqual(baseStorage.useSaasBucket, false);

process.env.HP_DEPLOYMENT_MODE = 'saas';
process.env.SAAS_WASABI_BUCKET = 'saaspipeshare';
const saasStorage = resolveStorageBackendForProcess();
assert.strictEqual(saasStorage.useSaasBucket, true);
assert.strictEqual(saasStorage.bucket, 'saaspipeshare');

console.log('deployment-profile + portal-storage-backend smoke OK');
