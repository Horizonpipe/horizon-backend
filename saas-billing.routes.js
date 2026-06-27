'use strict';

const express = require('express');
const {
  getStripe,
  stripeConfigured,
  resolveStripePriceId,
  mapStripeSubscriptionStatus,
  ensureTenantForBilling,
  findTenantByStripeCustomer,
  findTenantByStripeSubscription,
  findTenantByOwnerUserId,
  updateTenantSubscription,
  ensureStripeCustomer,
  resolveCheckoutUrls,
  billingStatusSummary,
  cleanString
} = require('./saas-billing.service');

function jsonError(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

async function applySubscriptionFromStripeObject(pool, subscription) {
  if (!subscription || typeof subscription !== 'object') return null;

  const customerId = cleanString(subscription.customer);
  const subscriptionId = cleanString(subscription.id);
  const status = mapStripeSubscriptionStatus(subscription.status);

  let tenant =
    (subscriptionId ? await findTenantByStripeSubscription(pool, subscriptionId) : null) ||
    (customerId ? await findTenantByStripeCustomer(pool, customerId) : null);

  const ownerUserId = cleanString(subscription.metadata?.owner_user_id);
  if (!tenant && ownerUserId) {
    tenant = await findTenantByOwnerUserId(pool, ownerUserId);
  }

  if (!tenant) {
    console.warn('[saas/billing/webhook] No tenant for subscription', subscriptionId || customerId);
    return null;
  }

  return updateTenantSubscription(
    pool,
    { tenantId: tenant.id },
    {
      subscriptionStatus: status,
      stripeCustomerId: customerId || tenant.stripeCustomerId,
      stripeSubscriptionId: subscriptionId || tenant.stripeSubscriptionId
    }
  );
}

async function handleCheckoutSessionCompleted(pool, stripe, session) {
  const ownerUserId = cleanString(session.metadata?.owner_user_id || session.client_reference_id);
  const customerId = cleanString(session.customer);
  const subscriptionId = cleanString(session.subscription);

  let tenant = null;
  if (ownerUserId) tenant = await findTenantByOwnerUserId(pool, ownerUserId);
  if (!tenant && customerId) tenant = await findTenantByStripeCustomer(pool, customerId);

  if (!tenant) {
    console.warn('[saas/billing/webhook] checkout.session.completed without tenant', ownerUserId || customerId);
    return null;
  }

  let subscriptionStatus = 'active';
  if (subscriptionId && stripe) {
    try {
      const sub = await stripe.subscriptions.retrieve(subscriptionId);
      subscriptionStatus = mapStripeSubscriptionStatus(sub.status);
    } catch (error) {
      console.warn('[saas/billing/webhook] Could not retrieve subscription', subscriptionId, error.message);
    }
  }

  return updateTenantSubscription(
    pool,
    { tenantId: tenant.id },
    {
      subscriptionStatus,
      stripeCustomerId: customerId || tenant.stripeCustomerId,
      stripeSubscriptionId: subscriptionId || tenant.stripeSubscriptionId
    }
  );
}

/**
 * Mount BEFORE express.json() — Stripe signature verification needs raw body.
 * @param {import('express').Express} app
 * @param {{ pool: import('pg').Pool }} deps
 */
function registerSaasBillingWebhook(app, { pool }) {
  app.post('/saas/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const stripe = getStripe();
    const webhookSecret = cleanString(process.env.STRIPE_WEBHOOK_SECRET);

    if (!stripe || !webhookSecret) {
      return jsonError(res, 503, 'Stripe webhook is not configured');
    }

    const signature = req.headers['stripe-signature'];
    if (!signature) {
      return jsonError(res, 400, 'Missing Stripe signature');
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
    } catch (error) {
      console.error('[saas/billing/webhook] Signature verification failed:', error.message);
      return jsonError(res, 400, 'Invalid Stripe signature');
    }

    try {
      switch (event.type) {
        case 'checkout.session.completed':
          await handleCheckoutSessionCompleted(pool, stripe, event.data.object);
          break;
        case 'customer.subscription.created':
        case 'customer.subscription.updated':
          await applySubscriptionFromStripeObject(pool, event.data.object);
          break;
        case 'customer.subscription.deleted':
          await applySubscriptionFromStripeObject(pool, {
            ...event.data.object,
            status: 'canceled'
          });
          break;
        case 'invoice.payment_failed': {
          const invoice = event.data.object;
          const customerId = cleanString(invoice.customer);
          const subscriptionId = cleanString(invoice.subscription);
          let tenant =
            (subscriptionId ? await findTenantByStripeSubscription(pool, subscriptionId) : null) ||
            (customerId ? await findTenantByStripeCustomer(pool, customerId) : null);
          if (tenant) {
            await updateTenantSubscription(pool, { tenantId: tenant.id }, { subscriptionStatus: 'past_due' });
          }
          break;
        }
        default:
          break;
      }
      return res.json({ received: true });
    } catch (error) {
      console.error('[saas/billing/webhook]', event.type, error);
      return jsonError(res, 500, error.message || 'Webhook handler failed');
    }
  });

  console.log('[saas-billing] POST /saas/billing/webhook mounted (raw body)');
}

/**
 * @param {import('express').Express} app
 * @param {{
 *   pool: import('pg').Pool,
 *   requireAuth: import('express').RequestHandler
 * }} deps
 */
function registerSaasBillingRoutes(app, { pool, requireAuth }) {
  app.get('/saas/billing/status', requireAuth, async (req, res) => {
    try {
      const tenant = await findTenantByOwnerUserId(pool, req.user?.id);
      return res.json({ success: true, billing: billingStatusSummary(tenant) });
    } catch (error) {
      console.error('[saas/billing/status]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/billing/checkout-session', requireAuth, async (req, res) => {
    try {
      const stripe = getStripe();
      if (!stripeConfigured()) {
        return jsonError(res, 503, 'Stripe is not configured on this server');
      }

      const priceId = resolveStripePriceId();
      if (!priceId) {
        return jsonError(res, 503, 'STRIPE_PRICE_ID is not configured');
      }

      const tenant = await ensureTenantForBilling(pool, req.user?.id, req.user);
      const customer = await ensureStripeCustomer(stripe, pool, req.user, tenant);
      const urls = resolveCheckoutUrls(req.body);

      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        customer: customer.id,
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: urls.successUrl,
        cancel_url: urls.cancelUrl,
        client_reference_id: String(req.user?.id || ''),
        metadata: {
          owner_user_id: String(req.user?.id || ''),
          tenant_id: tenant?.id ? String(tenant.id) : ''
        },
        subscription_data: {
          metadata: {
            owner_user_id: String(req.user?.id || ''),
            tenant_id: tenant?.id ? String(tenant.id) : ''
          }
        },
        allow_promotion_codes: true
      });

      return res.json({
        success: true,
        sessionId: session.id,
        url: session.url
      });
    } catch (error) {
      console.error('[saas/billing/checkout-session]', error);
      return jsonError(res, 500, error.message || 'Could not create checkout session');
    }
  });

  app.get('/saas/billing/portal', requireAuth, async (req, res) => {
    try {
      const stripe = getStripe();
      if (!stripeConfigured()) {
        return jsonError(res, 503, 'Stripe is not configured on this server');
      }

      const tenant = await findTenantByOwnerUserId(pool, req.user?.id);
      if (!tenant?.stripeCustomerId) {
        return jsonError(res, 404, 'No Stripe customer linked to this account yet');
      }

      const cpanelBase = cleanString(process.env.SAAS_CPANEL_BASE_URL).replace(/\/$/, '');
      const returnUrl =
        cleanString(req.query.returnUrl) ||
        cleanString(process.env.STRIPE_PORTAL_RETURN_URL) ||
        (cpanelBase ? cpanelBase + '/horizonpipe-cpanel/billing.html' : '/horizonpipe-cpanel/billing.html');

      const portalSession = await stripe.billingPortal.sessions.create({
        customer: tenant.stripeCustomerId,
        return_url: returnUrl
      });

      return res.json({ success: true, url: portalSession.url });
    } catch (error) {
      console.error('[saas/billing/portal]', error);
      return jsonError(res, 500, error.message || 'Could not create portal session');
    }
  });

  console.log('[saas-billing] /saas/billing/* routes mounted');
}

module.exports = { registerSaasBillingWebhook, registerSaasBillingRoutes };
