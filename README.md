# Morti Projects - AI-Powered Requirements Gathering

A web application that gathers software requirements through natural voice conversations, then extracts structured designs and generates commercial proposals.

## Features

- **Voice Sessions**: WebRTC-based voice conversations via Vapi.ai for requirements discovery
- **AI Design Extraction**: Anthropic Claude analyses sessions to produce structured designs (customer-facing + engineering specs)
- **Proposal Generation**: OpenAI generates commercial pricing proposals from designs
- **Document Upload & Analysis**: PDF, DOCX, XLSX file parsing with AI-generated descriptions
- **Two Portals**: Admin portal for project management, customer portal for self-service
- **Mobile Support**: Dedicated mobile views at `/m/*` routes
- **Project Sharing**: Invite collaborators with admin/user/readonly permissions
- **Billing**: Stripe subscription management with automated payment dunning emails
- **Engine Integration**: Send approved designs to Morti Engine for automated builds

## Tech Stack

- **Backend**: Node.js, Express.js, EJS templates
- **Frontend**: Vanilla JavaScript (no framework)
- **Database**: PostgreSQL (production) / SQLite (local dev) — auto-selected by `database-adapter.js`
- **AI**: Anthropic Claude (design extraction, chat), OpenAI (file analysis, proposals, session analysis)
- **Voice**: Vapi.ai WebRTC SDK (loaded via CDN)
- **Billing**: Stripe (subscriptions, webhooks, portal)
- **Email**: Nodemailer (SMTP)
- **Auth**: JWT cookies, Google OAuth, TOTP MFA

## Quick Start

### Prerequisites

- Node.js (v18+)
- Anthropic API key
- OpenAI API key

### Installation

```bash
npm install
```

### Configuration

Create a `.env` file:

```bash
ANTHROPIC_API_KEY=your_key
OPENAI_API_KEY=your_key
JWT_SECRET=your_secret
# Optional:
# DATABASE_URL=postgres://...   (defaults to SQLite)
# STRIPE_SECRET_KEY=...
# STRIPE_WEBHOOK_SECRET=...
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=...
# SMTP_PASS=...
# GOOGLE_OAUTH_CLIENT_ID=...
# GOOGLE_OAUTH_CLIENT_SECRET=...
# DATA_DIR=./data
```

### Start

```bash
npm start
# Server runs on http://localhost:3000
# HTTPS on https://localhost:3443 (if certs/ exist)
```

Default admin login (SQLite): `luke@voicereq.ai` / `admin123`

## Project Structure

```
server.js                 # App init, middleware, route mounting (~200 lines)
database-adapter.js       # Auto-selects PostgreSQL or SQLite
auth.js                   # JWT + bcrypt auth helpers
billing.js                # Stripe SDK wrapper

helpers/
  paths.js                # DATA_DIR, DESIGNS_DIR, PROPOSALS_DIR, uploadsDir
  ids.js                  # Hashids encoding/decoding
  formatting.js           # Timezone helpers, HTML rendering, text formatting
  email-sender.js         # sendMortiEmail, sendSecurityAlert, sendInviteEmail
  generation-status.js    # Shared in-memory async generation status

middleware/
  rate-limiters.js        # Express rate limiters (general, login, upload, signup, contact)
  security.js             # XSS sanitization, Cloudflare middleware
  uploads.js              # Multer configs (disk + memory)
  auth-middleware.js      # apiAuth, optionalAuth, ownership/access verification

routes/
  public-pages.js         # Signup, about, contact, landing
  auth.js                 # Login/logout, MFA, Google OAuth
  profile.js              # Profile settings, password change
  admin-dashboard.js      # Admin dashboard, customer CRUD, feature requests
  admin-projects.js       # Admin project detail, archive, requirements
  design.js               # Design extraction, view, chat, publish, flowchart
  proposals.js            # Proposal generation, chat, publish, onboarding, engine
  sharing.js              # Project sharing (admin + customer)
  customer-mobile.js      # /m/* mobile routes
  customer.js             # Customer dashboard, project CRUD, voice sessions
  api.js                  # File upload, analyze, chat, sessions, export/import
  billing-routes.js       # Stripe webhook, billing CRUD, billing pages

views/                    # EJS templates
  admin/                  # Admin portal views
  customer/               # Customer portal views
    mobile/               # Mobile-specific views
public/                   # Static assets (JS, CSS, images)
  session.js              # VoiceSession class (Vapi.ai WebRTC)
emails.js                 # Email template functions
```

## Deployment

Hosted on Render.com (`render.yaml`). PostgreSQL for production, persistent disk at `/var/data` for uploads and file-based designs/proposals.

## License

MIT
