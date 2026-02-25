# Customer Grouping & Team Invite — Build Spec

**Status:** Approved, ready to build
**Date:** 2026-02-25
**Author:** Clara (from Luke's requirements)

---

## Overview

Decouple "customer" (company account) from "user" (individual login). Users belong to one or more customers, enabling team collaboration and consultant access across multiple companies.

---

## Database Schema

### `customers`
| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL PRIMARY KEY | |
| name | VARCHAR(255) NOT NULL | Company name, or user's personal name for solo users |
| abn | VARCHAR(20) NULL | Australian Business Number (optional for solo) |
| email_domain | VARCHAR(255) NULL | Extracted from owner's email. NULL for generic domains |
| engine_tenant_id | VARCHAR(255) NULL | For future engine tenant isolation |
| plan | VARCHAR(50) DEFAULT 'free' | Billing plan reference |
| created_at | TIMESTAMP DEFAULT NOW() | |
| updated_at | TIMESTAMP DEFAULT NOW() | |

### `customer_members`
| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL PRIMARY KEY | |
| customer_id | INTEGER NOT NULL FK→customers | |
| user_id | INTEGER NOT NULL FK→users | |
| role | VARCHAR(20) NOT NULL | 'owner', 'admin', or 'member' |
| invited_by | INTEGER NULL FK→users | NULL for auto-created owner |
| joined_at | TIMESTAMP DEFAULT NOW() | |
| UNIQUE(customer_id, user_id) | | One membership per customer per user |

### `customer_invites`
| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL PRIMARY KEY | |
| customer_id | INTEGER NOT NULL FK→customers | |
| email | VARCHAR(255) NOT NULL | Invitee email address |
| role | VARCHAR(20) DEFAULT 'member' | Role granted on accept |
| invited_by | INTEGER NOT NULL FK→users | |
| token | VARCHAR(64) NOT NULL UNIQUE | Secure random invite token |
| expires_at | TIMESTAMP NOT NULL | 7 days from creation |
| accepted_at | TIMESTAMP NULL | NULL until accepted |
| created_at | TIMESTAMP DEFAULT NOW() | |

### Schema changes to `projects`
| Column | Type | Notes |
|--------|------|-------|
| customer_id | INTEGER NULL FK→customers | Added column. Backfilled from owner's customer. |

---

## Roles & Permissions

| Action | Owner | Admin | Member |
|--------|-------|-------|--------|
| View projects | ✅ | ✅ | ✅ |
| Create projects | ✅ | ✅ | ✅ |
| Edit projects | ✅ | ✅ | ✅ (own only) |
| Delete projects | ✅ | ✅ | ❌ |
| Invite team members | ✅ | ✅ | ❌ |
| Remove team members | ✅ | ✅ (not owner) | ❌ |
| Change member roles | ✅ | ❌ | ❌ |
| Edit company details | ✅ | ❌ | ❌ |
| Manage billing | ✅ | ❌ | ❌ |
| Submit for design review | ✅ | ✅ | ✅ |

---

## Email Domain Rules

### Domain Extraction
- On customer creation, extract domain from owner's email: `luke@morti.com.au` → `morti.com.au`
- Store in `customers.email_domain`

### Blocked Domains (generic providers)
These domains are **never** used for domain matching:
- `gmail.com`
- `googlemail.com`
- `hotmail.com`
- `outlook.com`
- `yahoo.com`
- `live.com`
- `icloud.com`
- `aol.com`
- `protonmail.com`
- `proton.me`

If owner has a generic email → `email_domain` = NULL → domain matching disabled → owner must manually approve all invites.

### Invite Validation
1. Admin enters invitee email
2. Extract invitee domain
3. If `customer.email_domain` is set AND invitee domain matches → **auto-approve invite**
4. If domains don't match → **reject** (unless owner, who can override)
5. If `customer.email_domain` is NULL → only owner can invite (manual approval)

---

## Flows

### Signup (New User)
1. User signs up (email/password or Google OAuth)
2. Check `customer_invites` for pending invites matching their email
3. **If invite exists:**
   - Create user account
   - Add as `customer_member` with invite's role
   - Mark invite as accepted
   - Telegram notification to invite sender
4. **If no invite (new customer):**
   - Create user account
   - Auto-create `customers` row:
     - `name` = user's full name (solo user) or company name if provided
     - `email_domain` = extracted domain (NULL if generic)
   - Auto-create `customer_members` row (role = 'owner')
5. Admin approval still required for account activation (existing flow unchanged)

### Invite Team Member
1. Owner/admin navigates to Team Settings
2. Clicks "Invite Team Member"
3. Enters email address and selects role (admin/member)
4. Backend validates:
   - Caller has owner/admin role
   - Email domain matches `customer.email_domain` (or caller is owner)
   - No existing membership for this email
   - No pending unexpired invite for this email
5. Generate secure random token (32 bytes hex)
6. Create `customer_invites` row (expires in 7 days)
7. Send invite email with link: `https://projects.morti.com.au/invite/{token}`
8. Telegram notification to owner

### Accept Invite
1. User clicks invite link → `/invite/:token`
2. Validate token exists, not expired, not already accepted
3. **If user is logged in:**
   - Add `customer_member` row
   - Mark invite accepted
   - Redirect to dashboard (with customer switcher if multi-customer)
4. **If not logged in but account exists:**
   - Redirect to login, then back to invite acceptance
5. **If no account:**
   - Redirect to signup with email pre-filled
   - After signup + admin approval, auto-accept invite

### Solo → Company Conversion
1. Owner navigates to Company Settings
2. Edits company name, optionally adds ABN
3. `email_domain` recalculated if owner changes email
4. Team features become visible

---

## API Endpoints

### Customer Management
- `GET /api/customer` — Get current user's customer(s)
- `PUT /api/customer/:id` — Update customer details (owner only)
- `GET /api/customer/:id/members` — List team members
- `DELETE /api/customer/:id/members/:userId` — Remove member

### Invites
- `POST /api/customer/:id/invites` — Create invite (owner/admin)
- `GET /api/customer/:id/invites` — List pending invites
- `DELETE /api/customer/:id/invites/:inviteId` — Cancel invite
- `GET /invite/:token` — View/accept invite (public)
- `POST /invite/:token/accept` — Accept invite

### Admin
- `GET /admin/customers` — List all customers with member counts
- `GET /admin/customers/:id` — Customer detail (members, projects, billing)
- `POST /admin/customers/:id/assign-user` — Manually assign user to customer

---

## UI Changes

### Customer Dashboard
- Projects grouped under customer name
- If user belongs to multiple customers → **customer switcher** dropdown in nav
- Team members shown in sidebar or settings tab

### Team Settings Page (`/team` or tab in `/profile`)
- Member list with roles
- "Invite Team Member" button (owner/admin only)
- Pending invites list with cancel option
- Role change dropdown (owner only)
- Remove member button (owner/admin, not self)

### Admin Portal
- **Customers page** replaces or extends current users page
- Table: Customer name | Members | Projects | Plan | Created
- Click → detail page with members, projects, billing

### Company Settings (in Profile)
- Company name (editable by owner)
- ABN (optional)
- Email domain (auto-detected, display only)

---

## Migration Plan

### Step 1: Schema Migration (zero downtime)
```sql
-- Add tables
CREATE TABLE customers (...);
CREATE TABLE customer_members (...);
CREATE TABLE customer_invites (...);

-- Add column to projects
ALTER TABLE projects ADD COLUMN customer_id INTEGER REFERENCES customers(id);
```

### Step 2: Backfill Existing Data
```sql
-- Create a customer for each existing user
INSERT INTO customers (name, email_domain, created_at)
SELECT name, 
  CASE WHEN split_part(email, '@', 2) IN ('gmail.com','hotmail.com','outlook.com','yahoo.com','live.com','icloud.com','aol.com','protonmail.com','proton.me','googlemail.com')
    THEN NULL
    ELSE split_part(email, '@', 2)
  END,
  created_at
FROM users;

-- Create owner memberships
INSERT INTO customer_members (customer_id, user_id, role)
SELECT c.id, u.id, 'owner'
FROM users u
JOIN customers c ON c.name = u.name AND c.created_at = u.created_at;

-- Assign projects to customers
UPDATE projects p
SET customer_id = cm.customer_id
FROM customer_members cm
WHERE cm.user_id = p.user_id AND cm.role = 'owner';
```

### Step 3: Update Application Code
- Dashboard queries join through `customer_members` → `customers` → `projects`
- Project creation sets `customer_id`
- Auth middleware resolves user's customer(s)

### Step 4: Deploy
- Push migration + code together
- Backfill runs on startup (idempotent)
- Old user-based project queries still work (fallback)

---

## Engine Handoff
- When project is sent to Morti Engine, include `customer_id`
- Engine uses `customer_id` for:
  - Tenant isolation (future: separate n8n instances per customer)
  - Billing attribution
  - Access control on engine API

---

## Security Considerations
- Invite tokens: 32 bytes crypto random, single-use, 7-day expiry
- Domain matching: blocked generic providers, case-insensitive comparison
- Role escalation: only owners can promote to admin
- Cross-customer access: users only see projects for their customer(s)
- Audit logging: all invite/role/membership changes logged
- Rate limiting: max 10 invites per customer per hour

---

## Future Enhancements (Not Phase 1)
- Company logo upload
- Custom email domain verification (DNS TXT record)
- Per-customer branding
- Billing per customer (not per user)
- Customer-level API keys for engine integration
- Consultant mode: user belongs to multiple customers with different roles
