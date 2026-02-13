# Morti Projects — Technical Documentation

> AI-powered voice and text requirements gathering platform with portal, auth, and persistent storage.

**Live URL:** https://voicereq-ai.onrender.com  
**Repository:** https://github.com/lukemccarthyhome-art/voicereq-ai (private)  
**Local Dev:** https://localhost:3443 or http://localhost:3000

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Technology Stack](#technology-stack)
3. [Directory Structure](#directory-structure)
4. [Authentication & Authorization](#authentication--authorization)
5. [Database Layer](#database-layer)
6. [Voice Integration (Vapi.ai)](#voice-integration-vapiai)
7. [Session Management](#session-management)
8. [File Processing Pipeline](#file-processing-pipeline)
9. [Requirements Extraction Engine](#requirements-extraction-engine)
10. [Portal System](#portal-system)
11. [API Reference](#api-reference)
12. [Security](#security)
13. [Deployment (Render.com)](#deployment-rendercom)
14. [Local Development](#local-development)
15. [Environment Variables](#environment-variables)
16. [Key Design Decisions](#key-design-decisions)
17. [Known Limitations](#known-limitations)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                       Client (Browser)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Portal UI   │  │ Voice Session│  │  Vapi SDK     │  │
│  │  (EJS SSR)   │  │  (SPA)       │  │  (WebRTC)     │  │
│  └──────┬───────┘  └──────┬───────┘  └───────┬───────┘  │
└─────────┼─────────────────┼──────────────────┼──────────┘
          │                 │                  │
          │ HTTP/HTTPS      │ REST API         │ WebRTC
          │                 │                  │
┌─────────┼─────────────────┼──────────────────┼──────────┐
│         ▼                 ▼                  ▼          │
│  ┌─────────────────────────────┐    ┌───────────────┐   │
│  │      Express.js Server      │    │   Vapi.ai     │   │
│  │  (server.js — 987 lines)    │    │   Cloud       │   │
│  │                             │    │   (Voice AI)  │   │
│  │  • Auth (JWT + cookies)     │    └───────────────┘   │
│  │  • Portal routes (EJS)      │                        │
│  │  • REST API endpoints       │                        │
│  │  • File upload (multer)     │                        │
│  │  • AI analysis (OpenAI)     │                        │
│  └──────────┬──────────────────┘                        │
│             │                                           │
│  ┌──────────▼──────────────────┐                        │
│  │    Database Adapter         │                        │
│  │  (database-adapter.js)      │                        │
│  │                             │                        │
│  │  DATABASE_URL set?          │                        │
│  │  ├─ Yes → PostgreSQL (pg)   │                        │
│  │  └─ No  → SQLite            │                        │
│  └─────────────────────────────┘                        │
│                                                         │
│                    Render.com                            │
└─────────────────────────────────────────────────────────┘
```

The app is a monolithic Node.js server that serves both the portal (server-side rendered with EJS) and the voice session interface (client-side SPA). Voice AI runs entirely on Vapi.ai's infrastructure via WebRTC — the server never handles audio streams.

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Runtime** | Node.js | Server runtime |
| **Framework** | Express.js | HTTP server, routing, middleware |
| **Templating** | EJS | Server-side rendered portal pages |
| **Database (prod)** | PostgreSQL (pg) | Persistent data storage on Render |
| **Database (dev)** | SQLite (better-sqlite3) | Local development database |
| **Auth** | JWT + bcryptjs | Token-based auth with hashed passwords |
| **Voice AI** | Vapi.ai (HTML Script Tag SDK) | Real-time voice conversation via WebRTC |
| **LLM (server)** | OpenAI gpt-3.5-turbo | File analysis, requirements extraction, text chat |
| **LLM (voice)** | OpenAI gpt-4o (via Vapi) | Voice conversation AI (Vapi manages this) |
| **File Upload** | Multer | Multipart form handling |
| **PDF Parsing** | pdf-parse | Extract text from PDFs |
| **DOCX Parsing** | Mammoth | Extract text from Word documents |
| **Export** | Archiver | Zip file generation |
| **Security** | Helmet + express-rate-limit | HTTP headers, request throttling |
| **Hosting** | Render.com | Cloud deployment with PostgreSQL |
| **SSL (local)** | Self-signed certs | HTTPS for local dev (required for mic on iPhone) |

---

## Directory Structure

```
voicereq-app/
├── server.js                 # Main Express server (all routes + API)
├── auth.js                   # JWT auth, password hashing, middleware
├── database.js               # SQLite implementation
├── database-pg.js            # PostgreSQL implementation
├── database-adapter.js       # Auto-selects SQLite or PG based on env
├── package.json              # Dependencies and scripts
├── render.yaml               # Render.com deployment config
├── .env                      # Environment variables (local)
├── .gitignore
│
├── public/                   # Static client files
│   ├── voice-session.html    # Voice session SPA (HTML)
│   ├── session.js            # VoiceSession class (client logic)
│   └── app.js                # Legacy/shared client code
│
├── views/                    # EJS templates
│   ├── layout.ejs            # Base layout (nav, footer)
│   ├── login.ejs             # Login page
│   ├── profile.ejs           # Password change page
│   ├── error.ejs             # Error page
│   ├── admin/
│   │   ├── dashboard.ejs     # Admin home (stats, recent activity)
│   │   ├── customers.ejs     # Customer CRUD
│   │   ├── projects.ejs      # All projects list
│   │   └── project-detail.ejs # Project detail (sessions, files)
│   └── customer/
│       ├── dashboard.ejs     # Customer home
│       ├── projects.ejs      # Customer's projects
│       └── project.ejs       # Project detail + session launcher
│
├── certs/                    # Self-signed SSL (local dev only)
│   ├── cert.pem
│   └── key.pem
│
├── uploads/                  # Uploaded files (local dev)
└── data/                     # SQLite database file (local dev)
```

---

## Authentication & Authorization

### Flow

1. User submits email/password to `POST /login`
2. Server verifies against bcrypt hash in `users` table
3. On success, generates JWT containing `{id, email, role, name}`, expires in 7 days
4. JWT stored as `authToken` HTTP-only cookie (`secure: true` in production, `sameSite: 'lax'`)
5. All subsequent requests carry cookie automatically

### Middleware Chain

```
authenticate     → Verifies JWT from cookie, sets req.user, redirects to /login if invalid
requireAdmin     → Checks req.user.role === 'admin', returns 403 if not
requireCustomer  → Checks req.user.role === 'customer', returns 403 if not
apiAuth          → Same as authenticate but returns JSON 401 (for API routes)
```

### Route Protection

| Route Pattern | Protection |
|--------------|-----------|
| `GET /admin/*` | `authenticate` + `requireAdmin` |
| `GET /dashboard`, `/projects/*` | `authenticate` + `requireCustomer` |
| `GET /voice-session` | `authenticate` (any role) |
| `GET /profile` | `authenticate` (any role) |
| `POST/PUT/DELETE /api/*` | `apiAuth` |
| `GET /uploads/*` | JWT verified inline |
| `GET /login`, `/api/health` | Public |

### Roles

- **admin** — Full access: manage customers, view all projects, reset passwords
- **customer** — Own projects only: create projects, run voice sessions, manage files

### Seed User

On database initialization, a default admin is created:
- **Email:** luke@voicereq.ai
- **Password:** admin123

---

## Database Layer

### Adapter Pattern

`database-adapter.js` selects the implementation at startup:

```javascript
if (process.env.DATABASE_URL) {
  module.exports = require('./database-pg');   // PostgreSQL
} else {
  module.exports = require('./database');       // SQLite
}
```

Both modules export **identical async function signatures** and a `ready` promise that resolves when tables are created.

### Schema (4 tables)

```sql
users
├── id            SERIAL / INTEGER PRIMARY KEY
├── email         TEXT UNIQUE NOT NULL
├── password_hash TEXT NOT NULL
├── name          TEXT NOT NULL
├── company       TEXT NOT NULL
├── role          TEXT ('admin' | 'customer')
└── created_at    TIMESTAMP

projects
├── id            SERIAL / INTEGER PRIMARY KEY
├── user_id       INTEGER → users(id)
├── name          TEXT NOT NULL
├── description   TEXT
├── status        TEXT ('active' | 'completed' | 'archived')
├── created_at    TIMESTAMP
└── updated_at    TIMESTAMP

sessions
├── id            SERIAL / INTEGER PRIMARY KEY
├── project_id    INTEGER → projects(id)
├── transcript    TEXT (JSON array of {role, text})
├── requirements  TEXT (JSON object {category: [items]})
├── context       TEXT (JSON object — topic tracking, key facts)
├── status        TEXT ('active' | 'paused' | 'completed')
├── created_at    TIMESTAMP
└── updated_at    TIMESTAMP

files
├── id            SERIAL / INTEGER PRIMARY KEY
├── project_id    INTEGER → projects(id)
├── session_id    INTEGER → sessions(id) (nullable)
├── filename      TEXT NOT NULL
├── original_name TEXT NOT NULL
├── mime_type     TEXT
├── size          INTEGER
├── extracted_text TEXT
├── analysis      TEXT (JSON)
├── description   TEXT (AI-generated, user-editable)
└── created_at    TIMESTAMP
```

### PostgreSQL Specifics

- Uses `pg.Pool` with `connectionString` from `DATABASE_URL`
- SSL disabled for Render internal connections (hostname doesn't contain `.render.com` external pattern)
- Connection retry: 3 attempts with exponential backoff (2s, 4s, 6s)
- All queries use `$1, $2` parameterized syntax
- Insert operations use `RETURNING *` or `RETURNING id`

### SQLite Specifics

- All sync operations wrapped in `Promise.resolve()` for consistent async interface
- Database file at `./data/voicereq.db` (or `$DATA_DIR/voicereq.db`)
- Uses `better-sqlite3` (native module, compiled during `npm install`)

### Exported Functions

```
User:     getUser, getUserById, createUser, getAllUsers, updateUser, updateUserPassword, deleteUser
Project:  createProject, getProjectsByUser, getAllProjects, getProject, updateProject, deleteProject
Session:  createSession, getSessionsByProject, getSession, updateSession, getLatestSessionForProject
File:     createFile, getFilesByProject, getFilesBySession, getFile, deleteFile, updateFileDescription
Stats:    getStats
```

---

## Voice Integration (Vapi.ai)

### How It Works

Vapi.ai provides a fully managed voice AI pipeline:

```
User's Mic → WebRTC → Vapi Cloud → STT → LLM (GPT-4o) → TTS → WebRTC → User's Speaker
```

The VoiceReq server **never touches audio**. All voice processing happens on Vapi's infrastructure. The client loads Vapi's HTML Script Tag SDK which establishes a WebRTC connection directly to Vapi.

### Configuration

- **Public Key:** `b34ed3bb-5c71-43df-a191-9b91568a329b` (client-side, safe to expose)
- **Private Key:** `c651a531-2350-47ab-a6e7-86a7c92aae4e` (server-side only)
- **Assistant ID:** `55bd93be-541f-4870-ae3e-0c97763c12b3`

### SDK Loading

```javascript
// HTML Script Tag SDK (NOT the Web SDK — UMD bundle doesn't exist on CDN)
const script = document.createElement('script');
script.src = 'https://cdn.jsdelivr.net/gh/VapiAI/html-script-tag@latest/dist/assets/index.js';
script.onload = () => {
    this.vapi = window.vapiSDK.run({
        apiKey: 'b34ed3bb-...',
        assistant: '55bd93be-...',
        config: { hide: true }  // Hide default floating button
    });
};
```

### Call Lifecycle

1. **Fresh call** — Uses default assistant config. If files were uploaded pre-call, injects file contents into system prompt override.
2. **Resumed call** — Builds full context (transcript + requirements + files + topic tracking) and injects as system prompt. Includes `NEXT TOPIC TO COVER` directive.
3. **Mid-call file upload** — Stops current call, waits 1.5s, restarts with updated context (including new file).

### Events Handled

| Event | Behavior |
|-------|----------|
| `call-start` | Update UI to listening state |
| `call-end` | Reset UI, auto-save session |
| `speech-start` | Show "AI Speaking" (suppressed if AI is held) |
| `speech-end` | Show "Listening" |
| `message` (transcript final) | Append to transcript, track topics |
| `volume-level` | Update volume bar |
| `error` | Display error toast |

### "Hold AI" Feature

Allows user to pause AI responses while continuing to speak:

1. Interrupts AI speech via `vapi.say(' ', false, false)`
2. Mutes all `<audio>` elements in DOM (AI voice output)
3. Keeps user microphone live
4. Suppresses AI transcript messages while held
5. Auto-interrupts if AI tries to speak while held

### Assistant Tuning

Configured on Vapi dashboard:
- `responseDelay: 1.5s` — Waits before responding (prevents cutting off user)
- `waitSeconds: 1.8s` — Silence threshold before AI responds
- `smartEndpointing: true` — Better turn-taking detection

---

## Session Management

### Session State (Client-Side)

The `VoiceSession` class (`session.js`) manages all client state:

```javascript
{
    messages: [{role: 'ai'|'user', text: '...'}],  // Full transcript
    requirements: {                                  // Categorized requirements
        'Functional Requirements': ['...', '...'],
        'Stakeholders': ['...']
    },
    sessionContext: {
        projectName: '',
        topicsCovered: ['project_basics', 'stakeholders', ...],
        keyFacts: ['...'],
        currentTopic: '',
        filesUploaded: [{name, content}]
    },
    uploadedFiles: [{id, name, description, extracted_text, ...}]
}
```

### Persistence

- **Auto-save:** Every 30 seconds (if session has data)
- **Event-save:** After every 4th transcript message, on call end
- **Unload-save:** `navigator.sendBeacon()` on page close
- **Manual save:** After requirements edit, file upload, description change

### Session Resume

When loading `/voice-session?project=X&session=Y`:
1. Fetches `GET /api/sessions/:id` (includes associated files)
2. Restores transcript, requirements, context, file cards
3. Rebuilds `window.fileContents` from DB `extracted_text`
4. When voice call starts, full context injected into system prompt

---

## File Processing Pipeline

```
User drops file → POST /api/upload
                    │
                    ├─ Text extraction based on extension:
                    │   ├─ .txt/.md/.csv/.json/.xml/.html/.css/.js/.py → fs.readFileSync (UTF-8)
                    │   ├─ .doc/.docx → mammoth.extractRawText()
                    │   ├─ .pdf → PDFParse: new PDFParse(Uint8Array) → load() → getText()
                    │   └─ other → "[unsupported format]"
                    │
                    ├─ Truncate to 8000 chars if needed
                    │
                    ├─ Save to DB (files table: filename, mime_type, size, extracted_text)
                    │
                    ├─ Rename to original filename in uploads dir
                    │
                    └─ Generate AI description (async):
                        POST to OpenAI gpt-3.5-turbo
                        "What type of document is this? Key content? How could it inform requirements?"
                        → Save description to files.description
                    
                    ↓ Response to client
                    {filename, content, charCount, description, fileId}
                    
Client stores in window.fileContents[filename] = content
```

### File Context Injection

Files are **not** read aloud by the AI during calls. Instead:
- On call start/resume, file contents are embedded in the system prompt
- AI uses them as background knowledge to ask informed questions
- System prompt instructs: "Reference specific details when relevant but don't just read the documents aloud"

---

## Requirements Extraction Engine

### Philosophy

Requirements are populated **on-demand** via the "Refresh Requirements" button, not auto-categorized from each chat message. This gives the user control over when analysis happens and avoids noise from casual conversation.

### Flow

```
User clicks "🔄 Refresh Requirements"
    │
    ├─ Collect: transcript + fileContents + existing requirements
    │
    └─ POST /api/analyze-session
        │
        ├─ Build analysis content:
        │   ├─ ## CONVERSATION TRANSCRIPT
        │   ├─ ## UPLOADED DOCUMENTS (with AI descriptions)
        │   └─ ## ALREADY CAPTURED REQUIREMENTS (DO NOT REPEAT THESE)
        │
        └─ Send to OpenAI gpt-3.5-turbo with response_format: json_object
            │
            Returns:
            {
                requirements: { category: [items] },
                summary: "...",
                keyInsights: ["..."],
                documentReferences: ["..."]
            }
```

### Additive Merge (Critical Behavior)

The refresh **never modifies or removes** existing requirements:

```javascript
// Server: sends existing requirements with "DO NOT REPEAT" instruction
// Client: deduplicates before appending
for (const [cat, items] of Object.entries(newReqs)) {
    if (!this.requirements[cat]) {
        this.requirements[cat] = items;  // New category
    } else {
        const existing = new Set(this.requirements[cat].map(r => r.toLowerCase().trim()));
        const additions = items.filter(r => !existing.has(r.toLowerCase().trim()));
        this.requirements[cat] = [...this.requirements[cat], ...additions];
    }
}
```

### Inline Editing

All requirements are `contentEditable`:
- Click to edit text inline
- Empty text → requirement deleted
- ✕ button to delete
- "+ Add requirement" per category for manual additions
- All changes auto-save to DB

### Categories

Standard categories (displayed in order):
1. Project Overview
2. Stakeholders
3. Functional Requirements
4. Non-Functional Requirements
5. Constraints
6. Success Criteria
7. Business Rules

---

## Portal System

### Admin Portal (`/admin/*`)

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `GET /admin` | Stats (users, projects, sessions, companies), recent activity |
| Customers | `GET /admin/customers` | List, create, edit, delete customers; reset passwords |
| Projects | `GET /admin/projects` | All projects across all customers |
| Project Detail | `GET /admin/projects/:id` | Sessions, files, delete project |

### Customer Portal (`/dashboard`, `/projects/*`)

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `GET /dashboard` | Welcome, project list |
| Projects | `GET /projects` | List own projects, create new |
| Project Detail | `GET /projects/:id` | Sessions, files, launch voice session, delete project |
| Voice Session | `GET /projects/:id/session` | Creates/resumes session, redirects to voice UI |

### Shared

| Page | Route | Description |
|------|-------|-------------|
| Login | `GET/POST /login` | Email/password authentication |
| Profile | `GET /profile` | Change own password |
| Logout | `GET /logout` | Clear cookie, redirect to login |

### Template Hierarchy

All portal pages use `views/layout.ejs` which provides:
- Responsive nav bar with role-appropriate links
- Breadcrumb navigation
- Logout button
- Flash messages (success/error via query params)

The voice session page (`voice-session.html`) is a **standalone SPA** — not rendered via EJS — with its own header containing a 🏠 portal link and logout.

---

## API Reference

All API routes require `apiAuth` (JWT cookie). All request/response bodies are JSON.

### File Operations

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/upload` | `multipart/form-data: file, projectId?, sessionId?` | `{filename, content, charCount, description, fileId}` |
| `PUT` | `/api/files/:id/description` | `{description}` | `{success: true}` |
| `DELETE` | `/api/files/:id` | — | `{success: true}` |

### Analysis

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/analyze` | `{filename, content}` | `{summary, description, requirements: [{category, text}]}` |
| `POST` | `/api/analyze-session` | `{transcript, fileContents, sessionId, projectId, existingRequirements}` | `{requirements, summary, keyInsights, documentReferences}` |

### Chat

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/chat` | `{message, transcript?, fileContents?, sessionId?}` | `{response}` |

### Sessions

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `GET` | `/api/sessions/:id` | — | Session object + `files[]` |
| `PUT` | `/api/sessions/:id` | `{transcript, requirements, context, status}` | `{success: true}` |

### Export

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/export-zip` | `{requirementsDoc}` | `application/zip` binary |

### Health

| Method | Endpoint | Auth | Response |
|--------|----------|------|----------|
| `GET` | `/api/health` | None | `{status: 'healthy'}` |

---

## Security

### Headers
- **Helmet** enabled (CSP disabled for inline EJS scripts)
- `trust proxy` set for Render's load balancer

### Rate Limiting
- **Global:** 300 requests / 15 minutes per IP
- **Login:** 10 attempts / 15 minutes per IP

### Authentication
- JWT stored as HTTP-only cookie (no localStorage XSS risk)
- `secure: true` in production (HTTPS only)
- `sameSite: 'lax'` (CSRF protection)
- 7-day token expiry
- bcrypt password hashing (10 rounds)

### File Access
- Uploaded files served behind JWT verification (`/uploads/*`)
- File size limit: 10MB (multer)
- JSON body limit: 20MB

### Database
- Parameterized queries throughout (no SQL injection)
- User deletion cascades (projects → sessions → files)

---

## Deployment (Render.com)

### Infrastructure

| Resource | Type | Details |
|----------|------|---------|
| Web Service | `srv-d6793n3nv86c739j9r40` | Node.js, Starter plan |
| PostgreSQL | Internal DB | `voicereq` database |
| Persistent Disk | 1GB at `/var/data` | File uploads (requires Starter plan) |

### render.yaml

```yaml
services:
  - type: web
    name: voicereq-ai
    runtime: node
    buildCommand: npm install
    startCommand: node server.js
    plan: starter
    disk:
      name: voicereq-data
      mountPath: /var/data
      sizeGB: 1
```

### Deploy Process

1. Push to `main` branch on GitHub triggers auto-deploy
2. Render runs `npm install` (build step)
3. Render runs `node server.js` (start step)
4. Server connects to PostgreSQL via `DATABASE_URL`
5. Creates tables if not exist, seeds admin user
6. Starts listening on `$PORT` (assigned by Render)

### Manual Deploy

```bash
git push origin master:main
# Or via API:
curl -X POST -H "Authorization: Bearer $RENDER_API_KEY" \
  https://api.render.com/v1/services/srv-d6793n3nv86c739j9r40/deploys
```

### DATA_DIR Fallback

The server gracefully handles `DATA_DIR` being unwritable:
```javascript
if (process.env.DATA_DIR) {
  try {
    fs.mkdirSync(process.env.DATA_DIR, { recursive: true });
    uploadsDir = path.join(process.env.DATA_DIR, 'uploads');
  } catch (e) {
    uploadsDir = path.join(__dirname, 'uploads');  // Fallback
  }
}
```

---

## Local Development

### Prerequisites
- Node.js v18+
- npm

### Setup

```bash
cd voicereq-app
cp .env.example .env   # Or create .env with required vars
npm install
npm start
```

### Local Access

- **HTTP:** http://localhost:3000
- **HTTPS:** https://localhost:3443 (requires certs in `certs/`)
- **Network:** https://192.168.1.178:3443 (for iPhone testing)

### Generate Self-Signed Certs

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

HTTPS is required for microphone access on iPhone Safari.

### Local Database

SQLite is used automatically when `DATABASE_URL` is not set. Database file created at `data/voicereq.db`.

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3000` | HTTP port (Render sets this) |
| `NODE_ENV` | No | — | Set to `production` on Render |
| `DATABASE_URL` | No | — | PostgreSQL connection string. If absent, uses SQLite. |
| `DATA_DIR` | No | — | Persistent disk mount for uploads |
| `JWT_SECRET` | Yes | `voicereq-default-secret-...` | JWT signing key |
| `OPENAI_API_KEY` | Yes | — | OpenAI key (gpt-3.5-turbo for server-side analysis) |
| `VAPI_PUBLIC_KEY` | Yes | — | Vapi client-side API key |
| `VAPI_PRIVATE_KEY` | No | — | Vapi server-side key (for future API calls) |

---

## Key Design Decisions

### 1. Vapi HTML Script Tag SDK (not Web SDK)
The Vapi Web SDK UMD bundle doesn't exist on CDN (returns 404). The HTML Script Tag SDK works but doesn't support `add-message` for mid-call context injection. Workaround: stop and restart the call with updated system prompt.

### 2. Additive Requirements Only
Refresh never modifies existing requirements. The AI receives already-captured requirements with a "DO NOT REPEAT" instruction, and the client deduplicates by lowercase comparison before appending. Users can manually edit or delete.

### 3. Dual Database Support
SQLite for zero-config local dev, PostgreSQL for production persistence. The adapter pattern keeps all route handlers identical regardless of backend.

### 4. Server-Side Rendering for Portal, SPA for Voice
Portal pages use EJS for simple CRUD with form submissions and redirects. The voice session is a standalone SPA because it manages complex real-time state (WebRTC, transcript streaming, requirements editing).

### 5. File Context via System Prompt
Since the Vapi HTML SDK can't inject messages mid-call, file contents are included in the system prompt when starting/restarting a call. This means mid-call uploads trigger a call restart (brief interruption).

### 6. gpt-3.5-turbo for Server Analysis
The OpenAI account lacks gpt-4o-mini access. Vapi uses its own OpenAI key for voice (gpt-4o), but server-side analysis (file processing, requirements extraction, text chat) uses gpt-3.5-turbo.

### 7. Cookie Auth (not Bearer tokens)
Cookies with `httpOnly`, `secure`, `sameSite: 'lax'` provide better security than localStorage tokens for a web app. The JWT is automatically sent with every request without client-side JavaScript handling.

---

## Known Limitations

1. **Hold AI** — `vapi.say(' ')` may not reliably interrupt AI speech in all cases due to HTML SDK limitations. Audio muting works as a fallback.

2. **OpenAI Model Access** — Server-side key only has access to gpt-3.5-turbo. gpt-4o and gpt-4o-mini return permission errors.

3. **Persistent Disk** — Requires Render Starter plan ($7/mo) with payment info. Without it, uploaded files persist between deploys but are lost on cold restarts (DB data in PostgreSQL is always safe).

4. **File Text Extraction** — Limited to PDF, DOCX, and plain text formats. Images, spreadsheets, and other binary formats return placeholder text.

5. **pdf-parse API** — Uses the class-based API: `new PDFParse(Uint8Array)` → `load()` → `getText()` returning `{pages: [{text}]}`. Not the legacy `pdfParse(buffer)` style.

6. **Session Context Size** — Long conversations with many files may exceed system prompt token limits when resuming a call. Content is substring-limited but could still be large.

7. **Single Concurrent Session** — Each project has one active session at a time (most recent non-completed). Starting a new session from the portal reuses the existing active one.

---

*Generated 2026-02-13. Source: voicereq-app codebase.*
