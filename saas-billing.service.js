'use strict';

const { loadTenantByOwner, upsertTenantDraft, serializeTenantRow } = require('./tenant-provisioning.service');
const { SAAS_INITIAL_SUBSCRIPTION_STATUS } = require('./lib/saas-subscription-constants');

function cleanString(v) {
  return String(v ?? '').trim();
}

let stripeClient = null;

function getStripe() {
  const key = cleanString(process.env.STRIPE_SECRET_KEY);
  if (!key) return null;
  if (!stripeClient) {
    // eslint-disable-next-line global-require
    stripeClient = require('stripe')(key);
  }
  return stripeClient;
}

function stripeConfigured() {
  return Boolean(cleanString(process.env.STRIPE_SECRET_KEY));
}

function resolveStripePriceId() {
  const single = cleanString(process.env.STRIPE_PRICE_ID);
  if (single) return single;

  const multi = cleanString(process.env.STRIPE_PRICE_IDS);
  if (!multi) return '';

  if (multi.startsWith('{')) {
    try {
      const parsed = JSON.parse(multi);
      if (parsed && typeof parsed === 'object') {
        const first = Object.values(parsed).find((v) => cleanString(v));
        return cleanString(first);
      }
    } catch (_) {
      /* fall through */
    }
  }

  const parts = multi.split(',').map((p) => cleanString(p)).filter(Boolean);
  return parts[0] || '';
}

function mapStripeSubscriptionStatus(stripeStatus) {
  const s = cleanString(stripeStatus).toLowerCase();
  if (s === 'active') return 'active';
  if (s === 'trialing') return 'trialing';
  if (s === 'past_due' || s === 'unpaid' || s === 'paused') return 'past_due';
  if (s === 'canceled' || s === 'incomplete_expired') return 'canceled';
  return 'pending';
}

function defaultBusinessNameFromUser(user) {
  const company = cleanString(user?.company);
  if (company) return company;
  const display = cleanString(user?.displayName || user?.username);
  if (display) return display;
  const email = cleanString(user?.email);
  if (email.includes('@')) return email.split('@')[0] || 'My Business';
  return 'My Business';
}

async function ensureTenantForBilling(pool, ownerUserId, user) {
  let tenant = await loadTenantByOwner(pool, ownerUserId);
  if (tenant) return tenant;
  return upsertTenantDraft(pool, ownerUserId, {
    businessName: defaultBusinessNameFromUser(user),
    websiteUrl: '',
    branding: { businessName: defaultBusinessNameFromUser(user) }
  });
}

async function findTenantByStripeCustomer(pool, customerId) {
  const id = cleanString(customerId);
  if (!id) return null;
  const r = await pool.query(
    `SELECT *
     FROM saas_tenant_instances
     WHERE stripe_customer_id = $1
     LIMIT 1`,
    [id]
  );
  return serializeTenantRow(r.rows[0] || null);
}

async function findTenantByStripeSubscription(pool, subscriptionId) {
  const id = cleanString(subscriptionId);
  if (!id) return null;
  const r = await pool.query(
    `SELECT *
     FROM saas_tenant_instances
     WHERE stripe_subscription_id = $1
     LIMIT 1`,
    [id]
  );
  return serializeTenantRow(r.rows[0] || null);
}

async function findTenantByOwnerUserId(pool, ownerUserId) {
  return loadTenantByOwner(pool, ownerUserId);
}

async function updateTenantSubscription(pool, lookup, fields) {
  const subscriptionStatus = fields.subscriptionStatus
    ? cleanString(fields.subscriptionStatus).toLowerCase()
    : null;
  const stripeCustomerId = fields.stripeCustomerId != null ? cleanString(fields.stripeCustomerId) : null;
  const stripeSubscriptionId =
    fields.stripeSubscriptionId != null ? cleanString(fields.stripeSubscriptionId) : null;

  let whereClause = '';
  let whereValue = '';
  if (lookup.ownerUserId) {
    whereClause = 'owner_user_id = $1';
    whereValue = String(lookup.ownerUserId);
  } else if (lookup.stripeCustomerId) {
    whereClause = 'stripe_customer_id = $1';
    whereValue = cleanString(lookup.stripeCustomerId);
  } else if (lookup.stripeSubscriptionId) {
    whereClause = 'stripe_subscription_id = $1';
    whereValue = cleanString(lookup.stripeSubscriptionId);
  } else if (lookup.tenantId) {
    whereClause = 'id = $1';
    whereValue = String(lookup.tenantId);
  } else {
    throw new Error('Missing tenant lookup key');
  }

  const sets = ['updated_at = NOW()'];
  const params = [whereValue];
  let idx = 2;

  if (subscriptionStatus) {
    sets.push(`subscription_status = $${idx}`);
    params.push(subscriptionStatus);
    idx += 1;
  }
  if (stripeCustomerId) {
    sets.push(`stripe_customer_id = $${idx}`);
    params.push(stripeCustomerId);
    idx += 1;
  }
  if (stripeSubscriptionId) {
    sets.push(`stripe_subscription_id = $${idx}`);
    params.push(stripeSubscriptionId);
    idx += 1;
  }

  const r = await pool.query(
    `UPDATE saas_tenant_instances
     SET ${sets.join(', ')}
     WHERE ${whereClause}
     RETURNING *`,
    params
  );
  return serializeTenantRow(r.rows[0] || null);
}

/** Pull subscription state from Stripe when webhooks lag or were missed. */
async function syncTenantSubscriptionFromStripe(stripe, pool, tenant) {
  if (!stripe || !tenant) return tenant;
  const customerId = cleanString(tenant.stripeCustomerId);
  if (!customerId) return tenant;

  let subscription = null;
  const subId = cleanString(tenant.stripeSubscriptionId);
  if (subId) {
    try {
      subscription = await stripe.subscriptions.retrieve(subId);
    } catch (_) {
      subscription = null;
    }
  }

  if (!subscription) {
    const list = await stripe.subscriptions.list({
      customer: customerId,
      status: 'all',
      limit: 10
    });
    const rows = list.data || [];
    subscription =
      rows.find((s) => s.status === 'active' || s.status === 'trialing') || rows[0] || null;
  }

  if (!subscription) return tenant;

  const mapped = mapStripeSubscriptionStatus(subscription.status);
  const current = cleanString(tenant.subscriptionStatus).toLowerCase();
  if (mapped === current && cleanString(tenant.stripeSubscriptionId) === cleanString(subscription.id)) {
    return tenant;
  }

  return updateTenantSubscription(pool, { tenantId: tenant.id }, {
    subscriptionStatus: mapped,
    stripeCustomerId: customerId,
    stripeSubscriptionId: subscription.id
  });
}

async function ensureStripeCustomer(stripe, pool, user, tenant) {
  if (tenant?.stripeCustomerId) {
    try {
      const existing = await stripe.customers.retrieve(tenant.stripeCustomerId);
      if (existing && !existing.deleted) return existing;
    } catch (_) {
      /* create fresh customer below */
    }
  }

  const email = cleanString(user?.email);
  const name = cleanString(user?.displayName || user?.username);
  const customer = await stripe.customers.create({
    email: email || undefined,
    name: name || undefined,
    metadata: {
      owner_user_id: String(user?.id || tenant?.ownerUserId || ''),
      tenant_id: tenant?.id ? String(tenant.id) : ''
    }
  });

  await updateTenantSubscription(pool, { ownerUserId: tenant.ownerUserId }, {
    stripeCustomerId: customer.id
  });

  return customer;
}

function resolveCheckoutUrls(reqBody) {
  const cpanelBase = cleanString(process.env.SAAS_CPANEL_BASE_URL).replace(/\/$/, '');
  const defaultSuccess = cpanelBase
    ? cpanelBase + '/horizonpipe-cpanel/index.html?billing=success'
    : '';
  const defaultCancel = cpanelBase
    ? cpanelBase + '/horizonpipe-cpanel/index.html?billing=canceled'
    : '';

  const success =
    cleanString(reqBody?.successUrl) ||
    cleanString(process.env.STRIPE_SUCCESS_URL) ||
    defaultSuccess;
  const cancel =
    cleanString(reqBody?.cancelUrl) ||
    cleanString(process.env.STRIPE_CANCEL_URL) ||
    defaultCancel;

  if (!success || !cancel) {
    throw new Error(
      'Checkout return URLs are required (pass successUrl/cancelUrl or set STRIPE_SUCCESS_URL / STRIPE_CANCEL_URL / SAAS_CPANEL_BASE_URL)'
    );
  }

  return { successUrl: success, cancelUrl: cancel };
}

function billingStatusSummary(tenant) {
  if (!tenant) {
    return {
      configured: stripeConfigured(),
      hasTenant: false,
      subscriptionStatus: SAAS_INITIAL_SUBSCRIPTION_STATUS,
      stripeCustomerId: '',
      stripeSubscriptionId: '',
      allowsProvisioning: false
    };
  }

  const status = tenant.subscriptionStatus || SAAS_INITIAL_SUBSCRIPTION_STATUS;
  const allows =
    process.env.SAAS_SKIP_SUBSCRIPTION_CHECK === '1' || status === 'active' || status === 'trialing';

  return {
    configured: stripeConfigured(),
    hasTenant: true,
    subscriptionStatus: status,
    stripeCustomerId: tenant.stripeCustomerId || '',
    stripeSubscriptionId: tenant.stripeSubscriptionId || '',
    setupStatus: tenant.setupStatus || 'draft',
    allowsProvisioning: allows,
    tenant
  };
}

module.exports = {
  cleanString,
  getStripe,
  stripeConfigured,
  resolveStripePriceId,
  mapStripeSubscriptionStatus,
  ensureTenantForBilling,
  findTenantByStripeCustomer,
  findTenantByStripeSubscription,
  findTenantByOwnerUserId,
  updateTenantSubscription,
  syncTenantSubscriptionFromStripe,
  ensureStripeCustomer,
  resolveCheckoutUrls,
  billingStatusSummary,
  SAAS_INITIAL_SUBSCRIPTION_STATUS
};
