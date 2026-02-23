/**
 * Billing Service — Stripe SDK wrapper for Morti Projects
 * Handles customer creation, subscription management, webhook parsing.
 * Gracefully handles missing Stripe keys (logs warning, doesn't crash).
 */

let stripe = null;

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

if (STRIPE_SECRET_KEY) {
  try {
    stripe = require('stripe')(STRIPE_SECRET_KEY);
    console.log('✅ Stripe SDK initialized');
  } catch (e) {
    console.warn('⚠️  Stripe SDK failed to initialize:', e.message);
  }
} else {
  console.warn('⚠️  STRIPE_SECRET_KEY not set — billing features disabled');
}

function isEnabled() {
  return !!stripe;
}

// ==================== Customer Management ====================

async function createCustomer({ email, name, metadata = {} }) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.customers.create({ email, name, metadata });
}

async function getCustomer(stripeCustomerId) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.customers.retrieve(stripeCustomerId);
}

// ==================== Subscription Management ====================

async function createSubscription({ customerId, priceData, setupAmount, metadata = {} }) {
  if (!stripe) throw new Error('Stripe not configured');

  const items = [];

  // Recurring monthly charge
  items.push({
    price_data: {
      currency: 'aud',
      product_data: { name: priceData.planName || 'Morti Automation' },
      unit_amount: priceData.monthlyAmount, // cents
      recurring: { interval: 'month' }
    }
  });

  const subParams = {
    customer: customerId,
    items,
    metadata,
    payment_behavior: 'default_incomplete',
    expand: ['latest_invoice.payment_intent']
  };

  // Add setup fee as a one-time invoice item before creating subscription
  if (setupAmount && setupAmount > 0) {
    await stripe.invoiceItems.create({
      customer: customerId,
      amount: setupAmount,
      currency: 'aud',
      description: 'Setup fee'
    });
  }

  return stripe.subscriptions.create(subParams);
}

async function getSubscription(stripeSubscriptionId) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.subscriptions.retrieve(stripeSubscriptionId);
}

async function pauseSubscription(stripeSubscriptionId) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.subscriptions.update(stripeSubscriptionId, {
    pause_collection: { behavior: 'void' }
  });
}

async function resumeSubscription(stripeSubscriptionId) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.subscriptions.update(stripeSubscriptionId, {
    pause_collection: ''
  });
}

async function cancelSubscription(stripeSubscriptionId) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.subscriptions.cancel(stripeSubscriptionId);
}

// ==================== Billing Portal ====================

async function createPortalSession(customerId, returnUrl) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: returnUrl
  });
}

// ==================== Webhook Parsing ====================

function constructWebhookEvent(rawBody, signature) {
  if (!stripe) throw new Error('Stripe not configured');
  if (!STRIPE_WEBHOOK_SECRET) throw new Error('STRIPE_WEBHOOK_SECRET not set');
  return stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET);
}

// ==================== Invoices ====================

async function listInvoices(customerId, limit = 20) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.invoices.list({ customer: customerId, limit });
}

async function getUpcomingInvoice(customerId) {
  if (!stripe) throw new Error('Stripe not configured');
  return stripe.invoices.retrieveUpcoming({ customer: customerId });
}

module.exports = {
  isEnabled,
  createCustomer,
  getCustomer,
  createSubscription,
  getSubscription,
  pauseSubscription,
  resumeSubscription,
  cancelSubscription,
  createPortalSession,
  constructWebhookEvent,
  listInvoices,
  getUpcomingInvoice
};
