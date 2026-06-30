import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { tenantUsersWhereSql, userRowIsTenantBound } = require('../lib/saas-tenant-scope.js');

const sql = tenantUsersWhereSql(2);
assert.match(sql, /portal-users/i, 'tenant user filter allows legacy portal-users when membership matches');

assert.equal(userRowIsTenantBound({ portal_files_client_id: 'tenant-acme' }), true);
assert.equal(userRowIsTenantBound({ portal_files_client_id: 'portal-users' }), false);

console.log('saas-tenant-scope.test.mjs: ok');
