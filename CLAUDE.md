# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Morti Projects is a modular Express.js application for AI-powered software requirements gathering through voice conversations. It uses server-side rendered EJS templates, vanilla JavaScript on the frontend, and Vapi.ai WebRTC for voice sessions.

## Commands

```bash
npm start          # Start the server (port 3000)
npm run dev        # Same as npm start (no hot reload)
```

There is no build step, test suite, or linter configured.

## Architecture

### Server Entry Point

`server.js` (~200 lines) is the Express application entry point. It handles app initialization, global middleware, Google OAuth setup, view engine config, template locals, `app.param` ID decoding, static file serving, route module mounting, error handling, and server startup.

### Module Structure

```
helpers/
  paths.js              — DATA_DIR, DESIGNS_DIR, PROPOSALS_DIR, uploadsDir
  ids.js                — Hashids instance, encodeProjectId, resolveProjectId
  formatting.js         — melb, melbDate, escapeHtml, renderText, summarizeRequirements
  email-sender.js       — sendMortiEmail, sendSecurityAlert, sendInviteEmail, isValidEmail
  generation-status.js  — shared in-memory status object for async design/proposal generation

middleware/
  rate-limiters.js      — generalLimiter, loginLimiter, uploadLimiter, signupLimiter, contactLimiter
  security.js           — sanitizeInput (XSS), cloudflareOnly
  uploads.js            — multer configs (upload disk 10MB, importUpload memory 50MB)
  auth-middleware.js    — apiAuth, optionalAuth, verifySessionOwnership, verifyProjectOwnership,
                           verifyProjectAccess, verifyFileOwnership, PERMISSION_LEVELS

routes/
  public-pages.js       — signup, about, contact, landing page
  auth.js               — login/logout, MFA, Google OAuth callbacks
  profile.js            — profile settings, password change, help page
  admin-dashboard.js    — /admin dashboard, customer CRUD, feature requests
  admin-projects.js     — admin project detail, archive, requirements, sessions
  design.js             — design extraction (extractDesignAsync), view, chat, publish, flowchart
  proposals.js          — proposal generation, chat, publish, approval, onboarding, send-to-engine
  sharing.js            — admin + customer share CRUD
  customer-mobile.js    — /m/* mobile routes
  customer.js           — customer dashboard, project CRUD, voice session
  api.js                — file upload, analyze, chat, sessions, export/import, health, backup
  billing-routes.js     — Stripe webhook, billing email templates, billing CRUD, billing pages
```

Each route file creates an Express Router with full paths (no prefix mounting) and exports it. Cross-module exports: `design.js` exports `loadNewestDesign`, `saveDesign`; `proposals.js` exports `loadNewestProposal`, `getEngineBuildId`.

### Database Dual-Mode

`database-adapter.js` selects the backend automatically:
- **PostgreSQL** when `DATABASE_URL` is set (production on Render)
- **SQLite** (better-sqlite3) when no `DATABASE_URL` (local development)

Both `database.js` (SQLite) and `database-pg.js` (PostgreSQL) export the same interface. Tables are created via `CREATE TABLE IF NOT EXISTS` in `initDB()`. Schema changes are applied as `ALTER TABLE` statements wrapped in try/catch. There is no migration tool.

SQLite seed user: `luke@voicereq.ai` / `admin123` (role: admin).

### Auth System

`auth.js` handles JWT generation and bcrypt password hashing. Tokens are stored in HTTP-only cookies (`authToken`), 2-hour expiry.

Key middleware:
- `authenticate` / `requireAdmin` / `requireCustomer` — in `auth.js` (page routes)
- `apiAuth` / `optionalAuth` — in `middleware/auth-middleware.js` (API routes)
- `verifyProjectOwnership` / `verifyProjectAccess(permission)` / `verifyFileOwnership` — in `middleware/auth-middleware.js`

Google OAuth via Passport. MFA via TOTP (otplib + qrcode).

### Two Portals

- **Admin portal** (`/admin/*`) — manage customers, projects, sessions, design extraction, proposals, billing
- **Customer portal** (`/dashboard`, `/projects/*`, `/customer/*`) — view projects, run voice sessions, view designs/proposals

Both use EJS templates in `views/`. Mobile-specific templates live in `views/customer/mobile/` and are served at `/m/*` routes.

### Voice Integration

Voice sessions use Vapi.ai's WebRTC SDK loaded via CDN script tag (not an npm package). Audio streams go directly between the browser and Vapi servers — no audio passes through Express. The browser sends transcripts and requirements to `/api/analyze-session` for server-side LLM enrichment.

Frontend voice session logic is in `public/session.js` (the `VoiceSession` class).

### AI/LLM Usage

- **Anthropic Claude** (primary): design extraction, proposal generation, chat endpoints
- **OpenAI**: file analysis, session analysis (fallback/secondary)

LLM prompts are inline in route handlers (`routes/design.js`, `routes/proposals.js`, `routes/api.js`).

### Billing

Stripe integration in `billing.js` (SDK wrapper) and `routes/billing-routes.js` (routes + email templates). Subscriptions, billing events, and payment history tracked in database. Webhook endpoint at `/api/billing/stripe-webhook` uses raw body parsing for signature verification — this raw body middleware is registered in `server.js` before `express.json()`.

### File Processing

Upload via Multer (10MB limit) to `DATA_DIR/uploads`. Parsers: pdf-parse (PDF), mammoth (DOCX), xlsx (spreadsheets). Files are linked to projects/sessions in the `files` table with extracted text stored for LLM analysis.

### Key Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | Production | PostgreSQL connection string |
| `JWT_SECRET` | Yes | JWT signing (auto-generated on Render) |
| `ANTHROPIC_API_KEY` | Yes | Claude API for design/proposal/chat |
| `OPENAI_API_KEY` | Yes | File/session analysis |
| `STRIPE_SECRET_KEY` | For billing | Stripe API |
| `STRIPE_WEBHOOK_SECRET` | For billing | Webhook signature verification |
| `SMTP_HOST/PORT/USER/PASS` | For emails | Nodemailer SMTP config |
| `GOOGLE_OAUTH_CLIENT_ID/SECRET` | For OAuth | Google SSO |
| `PORT` | No | Default 3000 |
| `DATA_DIR` | No | Default `./data` |

### Deployment

Hosted on Render.com (`render.yaml`). Build: `npm install`. Start: `node server.js`. Persistent disk at `/var/data` for uploads and SQLite data. PostgreSQL for production persistence.

**IMPORTANT: Dual-branch push required.** Local development is on `master`, but Render auto-deploys from `main`. After every push, always push to both:
```bash
git push origin master        # push to master
git push origin master:main   # push master to main for Render deploy
```
If you only push to `master`, changes will NOT go live on Render.

### Security Stack

Helmet (HTTP headers), express-rate-limit (300 req/15min general, 10 login/15min, 20 uploads/hr), XSS sanitization on request bodies, audit logging to database, Telegram alerts for security events.

## Conventions

- Pure JavaScript (no TypeScript)
- No frontend framework — vanilla JS with EJS server-side rendering
- Routes in `routes/*.js` as Express Routers with full paths (no prefix mounting, keeps routes greppable)
- Admin routes prefixed `/admin/`, API routes prefixed `/api/`, customer routes at `/dashboard`, `/projects/*`, `/customer/*`
- Shared state: `helpers/generation-status.js` exports a plain object imported by `design.js` and `proposals.js`
- Database functions exported as `db.functionName()` — both SQLite and PG modules must maintain the same interface
- New database fields added via `ALTER TABLE` in try/catch blocks within `initDB()`
- HTTPS via self-signed certs (`certs/`) for local dev (required for iOS microphone access)
