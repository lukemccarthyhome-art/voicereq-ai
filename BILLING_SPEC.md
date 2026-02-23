# Billing Module Spec — Morti Projects

## Context
- Existing tables: users, projects, sessions, files, audit_logs, feature_requests, project_shares
- No tenants/customers tables — use `users` table (customers have role='customer')
- Email: `sendMortiEmail(to, subject, html)` in server.js (nodemailer/SMTP)
- DB: Postgres (database-pg.js) with `CREATE TABLE IF NOT EXISTS` pattern
- Stripe keys not available yet — build everything, use placeholder env vars

## Database Schema (add to database-pg.js init)

### subscriptions
- id SERIAL PRIMARY KEY
- user_id INTEGER REFERENCES users(id)
- project_id INTEGER REFERENCES projects(id) 
- stripe_customer_id TEXT
- stripe_subscription_id TEXT UNIQUE
- status TEXT DEFAULT 'active' (active, past_due, paused, cancelled)
- plan_name TEXT
- monthly_amount INTEGER (cents)
- setup_amount INTEGER (cents)
- current_period_start TIMESTAMPTZ
- current_period_end TIMESTAMPTZ
- build_ids JSONB DEFAULT '[]'
- created_at TIMESTAMPTZ DEFAULT NOW()
- updated_at TIMESTAMPTZ DEFAULT NOW()

### billing_events
- id SERIAL PRIMARY KEY
- subscription_id INTEGER REFERENCES subscriptions(id)
- stripe_event_id TEXT UNIQUE
- event_type TEXT NOT NULL
- status TEXT (succeeded, failed, pending)
- amount INTEGER (cents)
- failure_reason TEXT
- attempt_count INTEGER DEFAULT 0
- raw_event JSONB
- created_at TIMESTAMPTZ DEFAULT NOW()

### payment_warnings
- id SERIAL PRIMARY KEY
- subscription_id INTEGER REFERENCES subscriptions(id)
- warning_type TEXT NOT NULL
- sent_at TIMESTAMPTZ DEFAULT NOW()
- email_to TEXT

## Flow
1. Admin approves proposal → "Activate Billing" button appears
2. Admin enters setup fee + monthly amount → creates Stripe subscription
3. Stripe charges setup + first month immediately
4. Webhook handles: invoice.paid, invoice.payment_failed, payment_method.expiring, subscription.deleted/updated
5. Failed payments escalate: warning → urgent → final → pause automation (POST Engine /api/billing/pause)
6. Card updated → auto-retry → resume (POST Engine /api/billing/resume)

## API Endpoints

### Customer-facing (auth required, role-gated to project owner)
- GET /api/billing/history?projectId=X — Payment history
- GET /api/billing/subscriptions?projectId=X — Active subscription
- POST /api/billing/update-card — Returns Stripe portal session URL

### Admin
- GET /api/admin/billing/overview — MRR, counts, alerts
- GET /api/admin/billing/tenant/:userId — Per-user billing
- POST /api/admin/billing/activate — Create subscription (setup + monthly)
- POST /api/admin/billing/pause — Manual pause
- POST /api/admin/billing/resume — Manual resume

### Webhook
- POST /api/billing/stripe-webhook — Stripe webhook handler (raw body)

## Email Templates (6)
1. receipt — Payment successful
2. card_expiry — Card expiring in 30 days
3. payment_failed_1 — First failure, will retry
4. payment_failed_2 — Urgent, update card
5. payment_failed_final — Final warning, pausing in 24hrs
6. automation_paused — Service paused
7. automation_resumed — Service restored

## UI
- Customer: billing tab on project page (history, subscription status, update card)
- Admin: billing section in admin portal (overview, per-project, activate billing button on approved proposals)
- Warning banners on dashboard when past_due or paused

## Engine Integration
- POST ENGINE_URL/api/billing/pause { userId, buildIds, reason }
- POST ENGINE_URL/api/billing/resume { userId, buildIds }
- Auth: Bearer ENGINE_API_SECRET header
