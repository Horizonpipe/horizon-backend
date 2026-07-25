'use strict';

/**
 * Tenant isolation for the reserved operator identity.
 * Every SaaS workspace may have its own "Mike"; only the BASE row is the platform operator.
 */

const {
  looksLikeMike,
  matchesPlatformOperatorIdentity,
  resolveHostingTier,
  deriveAccountModel,
  EMPLOYEE_ROLES
} = require('../capabilities');
const { isPlatformOperator } = require('../lib/saas-tenant-scope');

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`);
}

const baseMike = {
  id: '1',
  username: 'mik',
  display_name: 'Mike Strickland',
  email: 'mike@horizonpipe.com',
  portal_files_client_id: 'portal-users',
  is_admin: true,
  account_type: 'employee',
  employee_role: 'superadmin'
};

const tenantMikeStrickland = {
  id: '900',
  username: 'Mike Strickland',
  display_name: 'Mike Strickland',
  portal_files_client_id: 'tenant-acme',
  is_admin: true,
  account_type: 'employee',
  employee_role: 'admin'
};

const tenantPlainMike = {
  id: '901',
  username: 'Mike',
  display_name: 'Mike',
  portal_files_client_id: 'tenant-globex',
  account_type: 'employee',
  employee_role: 'camera-operator'
};

console.log('--- platform operator identity ---');
check('base operator is platform operator', looksLikeMike(baseMike), true);
check('base operator passes isPlatformOperator', isPlatformOperator(baseMike), true);
check('tenant "Mike Strickland" is NOT platform operator', looksLikeMike(tenantMikeStrickland), false);
check('tenant "Mike Strickland" fails isPlatformOperator', isPlatformOperator(tenantMikeStrickland), false);
check('tenant plain "Mike" is NOT platform operator', looksLikeMike(tenantPlainMike), false);
check(
  'camelCase tenant scope also blocks',
  looksLikeMike({ username: 'mik', portalFilesClientId: 'tenant-initech' }),
  false
);

console.log('--- reserved name still blocked on public signup ---');
check(
  'signup reservation matches by name alone',
  matchesPlatformOperatorIdentity({ email: 'mike@horizonpipe.com' }),
  true
);
check(
  'signup reservation ignores workspace binding',
  matchesPlatformOperatorIdentity({ username: 'Mike Strickland', portal_files_client_id: 'tenant-acme' }),
  true
);
check('signup reservation lets plain Mike through', matchesPlatformOperatorIdentity({ username: 'Mike' }), false);

console.log('--- derived role / hosting tier ---');
check('base operator hosting tier', resolveHostingTier(baseMike), 'base');
check('tenant "Mike Strickland" hosting tier', resolveHostingTier(tenantMikeStrickland), 'saas');
check(
  'tenant "Mike Strickland" is not auto-superadmin',
  deriveAccountModel(tenantMikeStrickland).employeeRole === EMPLOYEE_ROLES.SUPERADMIN,
  false
);
check(
  'base operator stays superadmin',
  deriveAccountModel(baseMike).employeeRole === EMPLOYEE_ROLES.SUPERADMIN,
  true
);

console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED');
process.exit(failures ? 1 : 0);
