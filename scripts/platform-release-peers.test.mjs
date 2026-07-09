import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  parsePlatformApplyPeerUrls,
  platformApplyPeerSecret,
  isPlatformApplyPeerConfigured,
  defaultSaasPlatformRequestHost
} = require('../lib/platform-release-peers.js');

assert.deepEqual(
  parsePlatformApplyPeerUrls({
    HP_PLATFORM_APPLY_PEER_URLS: 'https://pipeshare.net, https://saas2.example.com'
  }),
  ['https://pipeshare.net', 'https://saas2.example.com']
);

assert.equal(
  platformApplyPeerSecret({
    HP_PLATFORM_APPLY_PEER_SECRET: 'apply-secret',
    CP_SUPPORT_PRESENCE_PEER_SECRET: 'support-secret'
  }),
  'apply-secret'
);

assert.equal(
  platformApplyPeerSecret({
    CP_SUPPORT_PRESENCE_PEER_SECRET: 'support-secret'
  }),
  'support-secret'
);

assert.equal(
  isPlatformApplyPeerConfigured({
    HP_PLATFORM_APPLY_PEER_URLS: 'https://pipeshare.net',
    HP_PLATFORM_APPLY_PEER_SECRET: 'x'
  }),
  true
);

assert.equal(isPlatformApplyPeerConfigured({ HP_PLATFORM_APPLY_PEER_URLS: 'https://pipeshare.net' }), false);

assert.equal(defaultSaasPlatformRequestHost(), 'pipeshare.net');

console.log('platform-release-peers.test.mjs: ok');
