import assert from 'node:assert/strict';
import { isSaasSignupRequest, saasSignupHosts } from '../lib/saas-signup-context.js';

process.env.SAAS_CPANEL_BASE_URL = 'https://pipeshare.net';

assert.deepEqual([...saasSignupHosts()].sort(), ['pipeshare.net', 'www.pipeshare.net']);

assert.equal(
  isSaasSignupRequest({
    body: { signupContext: 'saas' },
    get: () => undefined
  }),
  true
);

assert.equal(
  isSaasSignupRequest({
    body: { signupContext: 'non-saas' },
    get: (h) => (h === 'origin' ? 'https://pipeshare.net' : undefined)
  }),
  false
);

assert.equal(
  isSaasSignupRequest({
    body: {},
    get: (h) => (h === 'origin' ? 'https://pipeshare.net' : undefined)
  }),
  true
);

assert.equal(
  isSaasSignupRequest({
    body: {},
    get: (h) => (h === 'origin' ? 'https://pipeshare.live' : undefined)
  }),
  false
);

console.log('saas-signup-context.test.mjs: ok');
