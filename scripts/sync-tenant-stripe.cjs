'use strict';
require('dotenv').config();
const pg = require('pg');
const {
  findTenantByOwnerUserId,
  syncTenantSubscriptionFromStripe,
  getStripe
} = require('../saas-billing.service');

(async () => {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const ownerId = process.argv[2] || '25';
  const before = await findTenantByOwnerUserId(pool, ownerId);
  const after = await syncTenantSubscriptionFromStripe(getStripe(), pool, before);
  console.log(
    JSON.stringify(
      {
        before: before && before.subscriptionStatus,
        after: after && after.subscriptionStatus,
        stripeSubscriptionId: after && after.stripeSubscriptionId
      },
      null,
      2
    )
  );
  await pool.end();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
