# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Morti Projects is a monolithic Express.js application for AI-powered software requirements gathering through voice conversations. It uses server-side rendered EJS templates, vanilla JavaScript on the frontend, and Vapi.ai WebRTC for voice sessions.

## Commands

```bash
npm start          # Start the server (port 3000)
npm run dev        # Same as npm start (no hot reload)
```

There is no build step, test suite, or linter configured.

## Architecture

### Server Entry Point

`server.js` (~5000 lines) is the Express application containing all routes, middleware, and business logic. There is no router modularization — all endpoints are defined inline.

### Database Dual-Mode

`database-adapter.js` selects the backend automatically:
- **PostgreSQL** when `DATABASE_URL` is set (production on Render)
- **SQLite** (better-sqlite3) when no `DATABASE_URL` (local development)

Both `database.js` (SQLite) and `database-pg.js` (PostgreSQL) export the same interface. Tables are created via `CREATE TABLE IF NOT EXISTS` in `initDB()`. Schema changes are applied as `ALTER TABLE` statements wrapped in try/catch. There is no migration tool.

SQLite seed user: `luke@voicereq.ai` / `admin123` (role: admin).

### Auth System

`auth.js` handles JWT generation and bcrypt password hashing. Tokens are stored in HTTP-only cookies (`authToken`), 2-hour expiry.

Key middleware in `server.js`:
- `authenticate` — verifies JWT, redirects to `/login` (for page routes)
- `apiAuth` — verifies JWT, returns 401 JSON (for API routes)
- `optionalAuth` — sets `req.user` if valid, doesn't block
- `requireAdmin` / `requireCustomer` — role checks
- `verifyProjectOwnership` / `verifyProjectAccess(permission)` — ownership and share-based access

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

LLM prompts are inline in `server.js` route handlers.

### Billing

Stripe integration in `billing.js`. Subscriptions, billing events, and payment history tracked in database. Webhook endpoint at `/api/billing/stripe-webhook` uses raw body parsing for signature verification — this route is registered before the JSON body parser middleware.

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

### Security Stack

Helmet (HTTP headers), express-rate-limit (300 req/15min general, 10 login/15min, 20 uploads/hr), XSS sanitization on request bodies, audit logging to database, Telegram alerts for security events.

## Conventions

- Pure JavaScript (no TypeScript)
- No frontend framework — vanilla JS with EJS server-side rendering
- All routes in `server.js` — admin routes prefixed `/admin/`, API routes prefixed `/api/`
- Database functions exported as `db.functionName()` — both SQLite and PG modules must maintain the same interface
- New database fields added via `ALTER TABLE` in try/catch blocks within `initDB()`
- HTTPS via self-signed certs (`certs/`) for local dev (required for iOS microphone access)
