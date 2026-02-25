const router = require('express').Router();
const db = require('../database-adapter');
const auth = require('../auth');
const billing = require('../billing');
const { resolveProjectId } = require('../helpers/ids');
const { apiAuth } = require('../middleware/auth-middleware');
const { sendMortiEmail } = require('../helpers/email-sender');

// Email templates for billing
const billingEmailTemplates = {
  receipt: (name, amount, date) => ({
    subject: 'Payment Received — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#1199fa;margin-bottom:20px;">Payment Received ✓</h1>
      <p>Hi ${name},</p>
      <p>We've received your payment of <strong>$${(amount/100).toFixed(2)} AUD</strong> on ${date}.</p>
      <p>Thank you for your continued trust in Morti Projects.</p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  card_expiry: (name, last4, expMonth, expYear) => ({
    subject: 'Card Expiring Soon — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#f59e0b;margin-bottom:20px;">⚠️ Card Expiring Soon</h1>
      <p>Hi ${name},</p>
      <p>Your card ending in <strong>${last4}</strong> expires <strong>${expMonth}/${expYear}</strong>.</p>
      <p>Please update your payment method to avoid service interruption.</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#1199fa;color:#fff;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Update Card</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  payment_failed_1: (name) => ({
    subject: 'Payment Failed — We\'ll Retry — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#f59e0b;margin-bottom:20px;">Payment Failed</h1>
      <p>Hi ${name},</p>
      <p>Your latest payment didn't go through. Don't worry — we'll automatically retry in a few days.</p>
      <p>If you'd like to update your payment method now:</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#1199fa;color:#fff;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Update Card</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  payment_failed_2: (name) => ({
    subject: 'Urgent: Payment Issue — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#ef4444;margin-bottom:20px;">⚠️ Urgent: Payment Issue</h1>
      <p>Hi ${name},</p>
      <p>We've been unable to process your payment after multiple attempts. Please update your payment method immediately to keep your automations running.</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#ef4444;color:#fff;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Update Payment Now</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  payment_failed_final: (name) => ({
    subject: 'Final Warning: Service Pausing in 24hrs — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#ef4444;margin-bottom:20px;">🚨 Final Warning</h1>
      <p>Hi ${name},</p>
      <p>Your payment has failed multiple times. <strong>Your automations will be paused in 24 hours</strong> unless payment is resolved.</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#ef4444;color:#fff;padding:14px 32px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Fix Payment Now</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  automation_paused: (name) => ({
    subject: 'Service Paused — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#ef4444;margin-bottom:20px;">⏸️ Service Paused</h1>
      <p>Hi ${name},</p>
      <p>Due to outstanding payment, your automations have been paused. Update your payment method to restore service immediately.</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#1199fa;color:#fff;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Restore Service</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  automation_resumed: (name) => ({
    subject: 'Service Restored ✓ — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#009e7e;margin-bottom:20px;">✅ Service Restored</h1>
      <p>Hi ${name},</p>
      <p>Your payment has been received and your automations are back up and running. Thank you!</p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  })
};

// Stripe Webhook Handler
router.post('/api/billing/stripe-webhook', async (req, res) => {
  if (!billing.isEnabled()) return res.status(200).json({ received: true, note: 'Stripe not configured' });

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = billing.constructWebhookEvent(req.body, sig);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'invoice.paid': {
        const invoice = event.data.object;
        const subId = invoice.subscription;
        const sub = await db.getSubscriptionByStripeId(subId);
        if (sub) {
          await db.updateSubscriptionStatus(sub.id, 'active');
          await db.createBillingEvent(sub.id, event.id, 'invoice.paid', 'succeeded', invoice.amount_paid, null, 0, event.data.object);
          if (invoice.lines && invoice.lines.data && invoice.lines.data[0]) {
            const line = invoice.lines.data[0];
            await db.updateSubscriptionPeriod(sub.id, new Date(line.period.start * 1000), new Date(line.period.end * 1000));
          }
          const user = await db.getUserById(sub.user_id);
          if (user) {
            const tmpl = billingEmailTemplates.receipt(user.name, invoice.amount_paid, new Date().toLocaleDateString('en-AU', { timeZone: 'Australia/Melbourne' }));
            sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
          }
          // If was past_due, resume engine
          if (sub.status === 'past_due' || sub.status === 'paused') {
            const engineUrl = process.env.ENGINE_API_URL;
            const engineSecret = process.env.ENGINE_API_SECRET;
            if (engineUrl && engineSecret) {
              try {
                await fetch(`${engineUrl}/api/billing/resume`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
                  body: JSON.stringify({ userId: sub.user_id, buildIds: sub.build_ids || [] })
                });
              } catch (e) { console.error('Engine resume failed:', e.message); }
            }
            if (user) {
              const tmpl = billingEmailTemplates.automation_resumed(user.name);
              sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
            }
          }
        }
        break;
      }
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const subId = invoice.subscription;
        const sub = await db.getSubscriptionByStripeId(subId);
        if (sub) {
          await db.updateSubscriptionStatus(sub.id, 'past_due');
          const attempt = invoice.attempt_count || 1;
          await db.createBillingEvent(sub.id, event.id, 'invoice.payment_failed', 'failed', invoice.amount_due, invoice.last_finalization_error?.message || 'Payment failed', attempt, event.data.object);

          const user = await db.getUserById(sub.user_id);
          if (user) {
            let tmpl;
            if (attempt <= 1) {
              tmpl = billingEmailTemplates.payment_failed_1(user.name);
              await db.createPaymentWarning(sub.id, 'payment_failed_1', user.email);
            } else if (attempt === 2) {
              tmpl = billingEmailTemplates.payment_failed_2(user.name);
              await db.createPaymentWarning(sub.id, 'payment_failed_2', user.email);
            } else {
              tmpl = billingEmailTemplates.payment_failed_final(user.name);
              await db.createPaymentWarning(sub.id, 'payment_failed_final', user.email);
              // Pause engine after final warning
              setTimeout(async () => {
                const engineUrl = process.env.ENGINE_API_URL;
                const engineSecret = process.env.ENGINE_API_SECRET;
                if (engineUrl && engineSecret) {
                  try {
                    await fetch(`${engineUrl}/api/billing/pause`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
                      body: JSON.stringify({ userId: sub.user_id, buildIds: sub.build_ids || [], reason: 'payment_failed' })
                    });
                    await db.updateSubscriptionStatus(sub.id, 'paused');
                    const pauseTmpl = billingEmailTemplates.automation_paused(user.name);
                    sendMortiEmail(user.email, pauseTmpl.subject, pauseTmpl.html).catch(() => {});
                  } catch (e) { console.error('Engine pause failed:', e.message); }
                }
              }, 24 * 60 * 60 * 1000);
            }
            if (tmpl) sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
          }
        }
        break;
      }
      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const sub = await db.getSubscriptionByStripeId(subscription.id);
        if (sub) {
          const statusMap = { active: 'active', past_due: 'past_due', canceled: 'cancelled', paused: 'paused' };
          const newStatus = statusMap[subscription.status] || subscription.status;
          await db.updateSubscriptionStatus(sub.id, newStatus);
          await db.createBillingEvent(sub.id, event.id, 'subscription.updated', newStatus, 0, null, 0, event.data.object);
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const sub = await db.getSubscriptionByStripeId(subscription.id);
        if (sub) {
          await db.updateSubscriptionStatus(sub.id, 'cancelled');
          await db.createBillingEvent(sub.id, event.id, 'subscription.deleted', 'cancelled', 0, null, 0, event.data.object);
        }
        break;
      }
      case 'payment_method.expiring': {
        const pm = event.data.object;
        if (pm.customer) {
          const subResult = await db.pool.query('SELECT s.*, u.name, u.email FROM subscriptions s JOIN users u ON u.id = s.user_id WHERE s.stripe_customer_id = $1 LIMIT 1', [pm.customer]);
          if (subResult.rows[0]) {
            const row = subResult.rows[0];
            const tmpl = billingEmailTemplates.card_expiry(row.name, pm.card?.last4 || '****', pm.card?.exp_month, pm.card?.exp_year);
            sendMortiEmail(row.email, tmpl.subject, tmpl.html).catch(() => {});
            await db.createPaymentWarning(row.id, 'card_expiry', row.email);
          }
        }
        break;
      }
    }
  } catch (e) {
    console.error('Webhook handler error:', e);
  }

  res.json({ received: true });
});

// Customer billing endpoints
router.get('/api/billing/subscriptions', apiAuth, async (req, res) => {
  try {
    const projectId = resolveProjectId(req.query.projectId);
    let subs;
    if (projectId) {
      const project = await db.getProject(projectId);
      if (!project || (req.user.role !== 'admin' && project.user_id !== req.user.id)) return res.status(403).json({ error: 'Forbidden' });
      subs = await db.getSubscriptionsByProject(projectId);
    } else {
      subs = await db.getSubscriptionsByUser(req.user.id);
    }
    res.json({ subscriptions: subs });
  } catch (e) {
    console.error('Get subscriptions error:', e);
    res.status(500).json({ error: 'Failed to fetch subscriptions' });
  }
});

router.get('/api/billing/history', apiAuth, async (req, res) => {
  try {
    const projectId = resolveProjectId(req.query.projectId);
    let subs;
    if (projectId) {
      const project = await db.getProject(projectId);
      if (!project || (req.user.role !== 'admin' && project.user_id !== req.user.id)) return res.status(403).json({ error: 'Forbidden' });
      subs = await db.getSubscriptionsByProject(projectId);
    } else {
      subs = await db.getSubscriptionsByUser(req.user.id);
    }
    let events = [];
    for (const sub of subs) {
      const subEvents = await db.getBillingEventsBySubscription(sub.id);
      events = events.concat(subEvents.map(e => ({ ...e, plan_name: sub.plan_name, project_name: sub.project_name })));
    }
    events.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json({ events });
  } catch (e) {
    console.error('Get billing history error:', e);
    res.status(500).json({ error: 'Failed to fetch billing history' });
  }
});

router.post('/api/billing/update-card', apiAuth, async (req, res) => {
  try {
    if (!billing.isEnabled()) return res.status(503).json({ error: 'Billing not configured' });
    const subs = await db.getSubscriptionsByUser(req.user.id);
    const activeSub = subs.find(s => s.stripe_customer_id);
    if (!activeSub) return res.status(404).json({ error: 'No active subscription found' });
    const returnUrl = (process.env.BASE_URL || 'https://projects.morti.com.au') + '/billing';
    const session = await billing.createPortalSession(activeSub.stripe_customer_id, returnUrl);
    res.json({ url: session.url });
  } catch (e) {
    console.error('Update card error:', e);
    res.status(500).json({ error: 'Failed to create portal session' });
  }
});

// Admin billing endpoints
router.get('/api/admin/billing/overview', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const overview = await db.getBillingOverview();
    res.json(overview);
  } catch (e) {
    console.error('Billing overview error:', e);
    res.status(500).json({ error: 'Failed to fetch billing overview' });
  }
});

router.get('/api/admin/billing/tenant/:userId', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const subs = await db.getSubscriptionsByUser(parseInt(req.params.userId));
    let events = [];
    for (const sub of subs) {
      const subEvents = await db.getBillingEventsBySubscription(sub.id);
      events = events.concat(subEvents);
    }
    res.json({ subscriptions: subs, events });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch tenant billing' });
  }
});

router.post('/api/admin/billing/activate', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { userId, projectId, planName, monthlyAmount, setupAmount, buildIds } = req.body;
    if (!userId || !monthlyAmount) return res.status(400).json({ error: 'userId and monthlyAmount required' });

    const user = await db.getUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!billing.isEnabled()) {
      const sub = await db.createSubscription(userId, projectId || null, null, `local_${Date.now()}`, planName || 'Morti Automation', monthlyAmount, setupAmount || 0, new Date(), new Date(Date.now() + 30 * 24 * 60 * 60 * 1000));
      if (buildIds) await db.pool.query('UPDATE subscriptions SET build_ids = $1 WHERE id = $2', [JSON.stringify(buildIds), sub.id]);
      return res.json({ subscription: sub, note: 'Created locally — Stripe not configured' });
    }

    const customer = await billing.createCustomer({ email: user.email, name: user.name, metadata: { userId: String(userId) } });

    const stripeSub = await billing.createSubscription({
      customerId: customer.id,
      priceData: { planName: planName || 'Morti Automation', monthlyAmount },
      setupAmount: setupAmount || 0,
      metadata: { userId: String(userId), projectId: String(projectId || '') }
    });

    const periodStart = stripeSub.current_period_start ? new Date(stripeSub.current_period_start * 1000) : new Date();
    const periodEnd = stripeSub.current_period_end ? new Date(stripeSub.current_period_end * 1000) : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    const sub = await db.createSubscription(userId, projectId || null, customer.id, stripeSub.id, planName || 'Morti Automation', monthlyAmount, setupAmount || 0, periodStart, periodEnd);
    if (buildIds) await db.pool.query('UPDATE subscriptions SET build_ids = $1 WHERE id = $2', [JSON.stringify(buildIds), sub.id]);

    await db.logAction(req.user.id, 'billing_activated', { userId, projectId, monthlyAmount, setupAmount }, req.ip);
    res.json({ subscription: sub, stripeSubscription: stripeSub });
  } catch (e) {
    console.error('Activate billing error:', e);
    res.status(500).json({ error: 'Failed to activate billing: ' + e.message });
  }
});

router.post('/api/admin/billing/pause', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { subscriptionId } = req.body;
    const subResult = await db.pool.query('SELECT * FROM subscriptions WHERE id = $1', [subscriptionId]);
    const sub = subResult.rows[0];
    if (!sub) return res.status(404).json({ error: 'Subscription not found' });

    if (billing.isEnabled() && sub.stripe_subscription_id && !sub.stripe_subscription_id.startsWith('local_')) {
      await billing.pauseSubscription(sub.stripe_subscription_id);
    }
    await db.updateSubscriptionStatus(sub.id, 'paused');

    const engineUrl = process.env.ENGINE_API_URL;
    const engineSecret = process.env.ENGINE_API_SECRET;
    if (engineUrl && engineSecret) {
      try {
        await fetch(`${engineUrl}/api/billing/pause`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
          body: JSON.stringify({ userId: sub.user_id, buildIds: sub.build_ids || [], reason: 'admin_pause' })
        });
      } catch (e) { console.error('Engine pause failed:', e.message); }
    }

    const user = await db.getUserById(sub.user_id);
    if (user) {
      const tmpl = billingEmailTemplates.automation_paused(user.name);
      sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
    }

    await db.logAction(req.user.id, 'billing_paused', { subscriptionId }, req.ip);
    res.json({ success: true });
  } catch (e) {
    console.error('Pause billing error:', e);
    res.status(500).json({ error: 'Failed to pause billing' });
  }
});

router.post('/api/admin/billing/resume', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { subscriptionId } = req.body;
    const subResult = await db.pool.query('SELECT * FROM subscriptions WHERE id = $1', [subscriptionId]);
    const sub = subResult.rows[0];
    if (!sub) return res.status(404).json({ error: 'Subscription not found' });

    if (billing.isEnabled() && sub.stripe_subscription_id && !sub.stripe_subscription_id.startsWith('local_')) {
      await billing.resumeSubscription(sub.stripe_subscription_id);
    }
    await db.updateSubscriptionStatus(sub.id, 'active');

    const engineUrl = process.env.ENGINE_API_URL;
    const engineSecret = process.env.ENGINE_API_SECRET;
    if (engineUrl && engineSecret) {
      try {
        await fetch(`${engineUrl}/api/billing/resume`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
          body: JSON.stringify({ userId: sub.user_id, buildIds: sub.build_ids || [] })
        });
      } catch (e) { console.error('Engine resume failed:', e.message); }
    }

    const user = await db.getUserById(sub.user_id);
    if (user) {
      const tmpl = billingEmailTemplates.automation_resumed(user.name);
      sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
    }

    await db.logAction(req.user.id, 'billing_resumed', { subscriptionId }, req.ip);
    res.json({ success: true });
  } catch (e) {
    console.error('Resume billing error:', e);
    res.status(500).json({ error: 'Failed to resume billing' });
  }
});

// Admin billing page
router.get('/admin/billing', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const overview = await db.getBillingOverview();
    const subscriptions = await db.getAllSubscriptions();
    res.render('admin/billing', { user: req.user, overview, subscriptions, currentPage: 'admin-billing', title: 'Billing Overview' });
  } catch (e) {
    console.error('Admin billing page error:', e);
    res.status(500).send('Failed to load billing page');
  }
});

// Customer billing page
router.get('/billing', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const subscriptions = await db.getSubscriptionsByUser(req.user.id);
    let events = [];
    for (const sub of subscriptions) {
      const subEvents = await db.getBillingEventsBySubscription(sub.id);
      events = events.concat(subEvents.map(e => ({ ...e, plan_name: sub.plan_name, project_name: sub.project_name })));
    }
    events.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.render('customer/billing', { user: req.user, subscriptions, events, currentPage: 'customer-billing', title: 'Billing', billingEnabled: billing.isEnabled() });
  } catch (e) {
    console.error('Customer billing page error:', e);
    res.status(500).send('Failed to load billing page');
  }
});

module.exports = router;
