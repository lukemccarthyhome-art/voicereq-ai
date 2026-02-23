const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// PostgreSQL connection pool using DATABASE_URL
const dbUrl = process.env.DATABASE_URL || '';
const needsSsl = dbUrl.includes('.render.com') ? false : 
                 (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false);

const pool = new Pool({
  connectionString: dbUrl,
  ssl: needsSsl,
  connectionTimeoutMillis: 10000,
});

// Initialize database tables with retry
const initDB = async (retries = 3) => {
  let client;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      client = await pool.connect();
      break;
    } catch (e) {
      console.error(`❌ PG connect attempt ${attempt}/${retries}:`, e.message);
      if (attempt === retries) throw e;
      await new Promise(r => setTimeout(r, 2000 * attempt));
    }
  }
  
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        company TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'active' CHECK (status IN ('active', 'completed', 'archived')),
        design_questions TEXT,
        admin_notes TEXT DEFAULT '[]',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL,
        transcript TEXT,
        requirements TEXT,
        context TEXT,
        status TEXT DEFAULT 'active' CHECK (status IN ('active', 'paused', 'completed')),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (project_id) REFERENCES projects (id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS files (
        id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL,
        session_id INTEGER,
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        mime_type TEXT,
        size INTEGER,
        extracted_text TEXT,
        analysis TEXT,
        description TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (project_id) REFERENCES projects (id),
        FOREIGN KEY (session_id) REFERENCES sessions (id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS feature_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        user_name TEXT,
        user_email TEXT,
        text TEXT NOT NULL,
        page TEXT,
        status TEXT DEFAULT 'new',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS project_shares (
        id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL,
        user_id INTEGER,
        email TEXT NOT NULL,
        permission TEXT NOT NULL DEFAULT 'readonly' CHECK (permission IN ('admin', 'user', 'readonly')),
        invited_by INTEGER NOT NULL,
        invited_at TIMESTAMP DEFAULT NOW(),
        accepted_at TIMESTAMP,
        invite_token TEXT,
        FOREIGN KEY (project_id) REFERENCES projects(id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (invited_by) REFERENCES users(id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        project_id INTEGER REFERENCES projects(id),
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT UNIQUE,
        status TEXT DEFAULT 'active',
        plan_name TEXT,
        monthly_amount INTEGER,
        setup_amount INTEGER,
        current_period_start TIMESTAMPTZ,
        current_period_end TIMESTAMPTZ,
        build_ids JSONB DEFAULT '[]',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS billing_events (
        id SERIAL PRIMARY KEY,
        subscription_id INTEGER REFERENCES subscriptions(id),
        stripe_event_id TEXT UNIQUE,
        event_type TEXT NOT NULL,
        status TEXT,
        amount INTEGER,
        failure_reason TEXT,
        attempt_count INTEGER DEFAULT 0,
        raw_event JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payment_warnings (
        id SERIAL PRIMARY KEY,
        subscription_id INTEGER REFERENCES subscriptions(id),
        warning_type TEXT NOT NULL,
        sent_at TIMESTAMPTZ DEFAULT NOW(),
        email_to TEXT
      )
    `);

    // Migrations
    try { await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT'); } catch (e) {}
    try { await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT'); } catch (e) {}
    try { await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS approved INTEGER DEFAULT 1'); } catch (e) {}
    try { await client.query('ALTER TABLE projects ADD COLUMN IF NOT EXISTS design_questions TEXT'); } catch (e) {}
    try { await client.query('ALTER TABLE projects ADD COLUMN IF NOT EXISTS admin_notes TEXT DEFAULT \'[]\''); } catch (e) {}
    try { await client.query('ALTER TABLE projects ADD COLUMN IF NOT EXISTS design_review_requested TIMESTAMP'); } catch (e) {}

    // Create seed admin user
    await createSeedUser();

    console.log('✅ PostgreSQL database initialized');
  } finally {
    client.release();
  }
};

const createSeedUser = async () => {
  const existingAdmin = await getUser('luke@voicereq.ai');
  if (!existingAdmin) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    await pool.query(`
      INSERT INTO users (email, password_hash, name, company, role)
      VALUES ($1, $2, $3, $4, $5)
    `, ['luke@voicereq.ai', hashedPassword, 'Luke McCarthy', 'Morti Projects', 'admin']);
    console.log('✅ Seed admin user created: luke@voicereq.ai / admin123');
  }
};

// ==================== User operations ====================

const getUser = async (email) => {
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return result.rows[0];
};

const getUserById = async (id) => {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return result.rows[0];
};

const createUser = async (email, name, company, role, plainPassword) => {
  const hashedPassword = bcrypt.hashSync(plainPassword, 10);
  const result = await pool.query(`
    INSERT INTO users (email, password_hash, name, company, role)
    VALUES ($1, $2, $3, $4, $5) RETURNING *
  `, [email, hashedPassword, name, company, role]);
  return { lastInsertRowid: result.rows[0].id, changes: 1 };
};

const getAllUsers = async () => {
  const result = await pool.query(`
    SELECT id, email, name, company, phone, role, approved, created_at 
    FROM users WHERE role = 'customer' ORDER BY created_at DESC
  `);
  return result.rows;
};

const updateUser = async (id, email, name, company) => {
  const result = await pool.query(
    'UPDATE users SET email = $1, name = $2, company = $3 WHERE id = $4',
    [email, name, company, id]
  );
  return { changes: result.rowCount };
};

const updateUserPassword = async (id, hashedPassword) => {
  const result = await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, id]);
  return { changes: result.rowCount };
};

const deleteUser = async (id) => {
  const projects = await pool.query('SELECT id FROM projects WHERE user_id = $1', [id]);
  for (const project of projects.rows) {
    await deleteProject(project.id);
  }
  await pool.query('DELETE FROM audit_logs WHERE user_id = $1', [id]);
  const result = await pool.query('DELETE FROM users WHERE id = $1', [id]);
  return { changes: result.rowCount };
};

// ==================== Project operations ====================

const createProject = async (userId, name, description) => {
  const result = await pool.query(`
    INSERT INTO projects (user_id, name, description) VALUES ($1, $2, $3) RETURNING *
  `, [userId, name, description || '']);
  return { lastInsertRowid: result.rows[0].id, changes: 1 };
};

const getProjectsByUser = async (userId) => {
  const result = await pool.query(`
    SELECT p.*, COUNT(DISTINCT s.id) as session_count, COUNT(DISTINCT f.id) as file_count
    FROM projects p
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE p.user_id = $1 AND (p.status IS NULL OR p.status != 'archived')
    GROUP BY p.id
    ORDER BY p.updated_at DESC
  `, [userId]);
  return result.rows;
};

const getArchivedProjectsByUser = async (userId) => {
  const result = await pool.query(`
    SELECT p.*, COUNT(DISTINCT s.id) as session_count, COUNT(DISTINCT f.id) as file_count
    FROM projects p
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE p.user_id = $1 AND p.status = 'archived'
    GROUP BY p.id
    ORDER BY p.updated_at DESC
  `, [userId]);
  return result.rows;
};

const getAllProjects = async () => {
  const result = await pool.query(`
    SELECT p.*, u.name as user_name, u.company, u.email,
           COUNT(DISTINCT s.id) as session_count, COUNT(DISTINCT f.id) as file_count
    FROM projects p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE (p.status IS NULL OR p.status != 'archived')
    GROUP BY p.id, u.name, u.company, u.email
    ORDER BY p.updated_at DESC
  `);
  return result.rows;
};

const getAllArchivedProjects = async () => {
  const result = await pool.query(`
    SELECT p.*, u.name as user_name, u.company, u.email,
           COUNT(DISTINCT s.id) as session_count, COUNT(DISTINCT f.id) as file_count
    FROM projects p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE p.status = 'archived'
    GROUP BY p.id, u.name, u.company, u.email
    ORDER BY p.updated_at DESC
  `);
  return result.rows;
};

const getProject = async (id) => {
  const result = await pool.query(`
    SELECT p.*, u.name as user_name, u.company, u.email
    FROM projects p
    JOIN users u ON u.id = p.user_id
    WHERE p.id = $1
  `, [id]);
  return result.rows[0];
};

const updateProject = async (id, name, description, status) => {
  const result = await pool.query(`
    UPDATE projects SET name = $1, description = $2, status = $3, updated_at = NOW() WHERE id = $4
  `, [name, description, status, id]);
  return { changes: result.rowCount };
};

const updateProjectDesignQuestions = async (id, json) => {
  const result = await pool.query(
    'UPDATE projects SET design_questions = $1, updated_at = NOW() WHERE id = $2',
    [json, id]
  );
  return { changes: result.rowCount };
};

const updateProjectAdminNotes = async (id, json) => {
  const result = await pool.query(
    'UPDATE projects SET admin_notes = $1, updated_at = NOW() WHERE id = $2',
    [json, id]
  );
  return { changes: result.rowCount };
};

const deleteProject = async (id) => {
  await pool.query('DELETE FROM files WHERE project_id = $1', [id]);
  await pool.query('DELETE FROM sessions WHERE project_id = $1', [id]);
  try { await pool.query('DELETE FROM project_shares WHERE project_id = $1', [id]); } catch(e) {}
  const result = await pool.query('DELETE FROM projects WHERE id = $1', [id]);
  return { changes: result.rowCount };
};

// ==================== Session operations ====================

const createSession = async (projectId) => {
  const result = await pool.query(`
    INSERT INTO sessions (project_id, transcript, requirements, context)
    VALUES ($1, $2, $3, $4) RETURNING *
  `, [projectId, '[]', '{}', '{}']);
  return { lastInsertRowid: result.rows[0].id, changes: 1 };
};

const getSessionsByProject = async (projectId) => {
  const result = await pool.query(`
    SELECT s.*, COUNT(f.id) as file_count
    FROM sessions s
    LEFT JOIN files f ON f.session_id = s.id
    WHERE s.project_id = $1
    GROUP BY s.id
    ORDER BY s.created_at DESC
  `, [projectId]);
  return result.rows;
};

const getSession = async (id) => {
  const result = await pool.query('SELECT * FROM sessions WHERE id = $1', [id]);
  return result.rows[0];
};

const updateSession = async (id, transcript, requirements, context, status) => {
  const result = await pool.query(`
    UPDATE sessions SET transcript = $1, requirements = $2, context = $3, status = $4, updated_at = NOW()
    WHERE id = $5
  `, [JSON.stringify(transcript), JSON.stringify(requirements), JSON.stringify(context), status, id]);
  return { changes: result.rowCount };
};

const getLatestSessionForProject = async (projectId) => {
  const result = await pool.query(`
    SELECT * FROM sessions WHERE project_id = $1 AND status != 'completed'
    ORDER BY updated_at DESC LIMIT 1
  `, [projectId]);
  return result.rows[0];
};

const appendSessionMessage = async (sessionId, message) => {
  if (!sessionId) throw new Error('sessionId required');
  const s = await pool.query('SELECT * FROM sessions WHERE id = $1', [sessionId]);
  if (!s.rows[0]) throw new Error('session not found');
  let transcript = [];
  try { transcript = JSON.parse(s.rows[0].transcript || '[]'); } catch { transcript = []; }
  transcript.push(message);
  await pool.query('UPDATE sessions SET transcript = $1, updated_at = NOW() WHERE id = $2', [JSON.stringify(transcript), sessionId]);
  return sessionId;
};

const appendSessionMessageSafe = async (projectId, message) => {
  const s = await pool.query(
    `SELECT * FROM sessions WHERE project_id = $1 AND status != 'completed' ORDER BY updated_at DESC LIMIT 1`,
    [projectId]
  );
  if (!s.rows[0]) {
    const res = await pool.query(
      'INSERT INTO sessions (project_id, transcript, requirements, context) VALUES ($1, $2, $3, $4) RETURNING id',
      [projectId, JSON.stringify([message]), '{}', '{}']
    );
    return res.rows[0].id;
  } else {
    const transcript = JSON.parse(s.rows[0].transcript || '[]');
    transcript.push(message);
    await pool.query('UPDATE sessions SET transcript = $1, updated_at = NOW() WHERE id = $2', [JSON.stringify(transcript), s.rows[0].id]);
    return s.rows[0].id;
  }
};

// ==================== File operations ====================

const createFile = async (projectId, sessionId, filename, originalName, mimeType, size, extractedText, analysis) => {
  const result = await pool.query(`
    INSERT INTO files (project_id, session_id, filename, original_name, mime_type, size, extracted_text, analysis)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *
  `, [projectId, sessionId, filename, originalName, mimeType, size, extractedText, analysis ? JSON.stringify(analysis) : null]);
  return { lastInsertRowid: result.rows[0].id, changes: 1 };
};

const getFileById = async (id) => {
  const result = await pool.query('SELECT * FROM files WHERE id = $1', [id]);
  return result.rows[0];
};

const getFilesByProject = async (projectId) => {
  const result = await pool.query(`
    SELECT f.*, s.status as session_status
    FROM files f
    LEFT JOIN sessions s ON s.id = f.session_id
    WHERE f.project_id = $1
    ORDER BY f.created_at DESC
  `, [projectId]);
  return result.rows;
};

const getFilesBySession = async (sessionId) => {
  const result = await pool.query('SELECT * FROM files WHERE session_id = $1 ORDER BY created_at DESC', [sessionId]);
  return result.rows;
};

const getFile = async (fileId) => {
  const result = await pool.query('SELECT * FROM files WHERE id = $1', [fileId]);
  return result.rows[0];
};

const deleteFile = async (fileId) => {
  const result = await pool.query('DELETE FROM files WHERE id = $1', [fileId]);
  return { changes: result.rowCount };
};

const updateFileDescription = async (fileId, description) => {
  const result = await pool.query('UPDATE files SET description = $1 WHERE id = $2', [description, fileId]);
  return { changes: result.rowCount };
};

// ==================== Audit logging ====================

const logAction = async (userId, action, details, ipAddress) => {
  try {
    await pool.query(
      'INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES ($1, $2, $3, $4)',
      [userId, action, JSON.stringify(details), ipAddress]
    );
  } catch (e) {
    console.error('❌ Failed to write audit log:', e.message);
  }
};

// ==================== Stats ====================

const getStats = async () => {
  const totalUsersResult = await pool.query(`SELECT COUNT(*) as count FROM users WHERE role = 'customer'`);
  const totalProjectsResult = await pool.query('SELECT COUNT(*) as count FROM projects');
  const totalSessionsResult = await pool.query('SELECT COUNT(*) as count FROM sessions');
  const companiesResult = await pool.query(`SELECT DISTINCT company FROM users WHERE role = 'customer'`);
  return {
    totalUsers: parseInt(totalUsersResult.rows[0].count),
    totalProjects: parseInt(totalProjectsResult.rows[0].count),
    totalSessions: parseInt(totalSessionsResult.rows[0].count),
    totalCompanies: companiesResult.rows.length
  };
};

// ==================== Sharing ====================

const shareProject = async (projectId, email, permission, invitedBy, inviteToken) => {
  const existing = await pool.query('SELECT id FROM project_shares WHERE project_id = $1 AND email = $2', [projectId, email]);
  if (existing.rows[0]) throw new Error('Already shared with this email');
  const countResult = await pool.query('SELECT COUNT(*) as c FROM project_shares WHERE project_id = $1', [projectId]);
  if (parseInt(countResult.rows[0].c) >= 20) throw new Error('Maximum 20 shares per project');
  const user = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  const result = await pool.query(
    'INSERT INTO project_shares (project_id, user_id, email, permission, invited_by, invite_token) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
    [projectId, user.rows[0] ? user.rows[0].id : null, email, permission, invitedBy, inviteToken || null]
  );
  return { lastInsertRowid: result.rows[0].id, changes: 1 };
};

const getProjectShares = async (projectId) => {
  const result = await pool.query(`
    SELECT ps.*, u.name as user_name, inv.name as inviter_name
    FROM project_shares ps
    LEFT JOIN users u ON u.id = ps.user_id
    LEFT JOIN users inv ON inv.id = ps.invited_by
    WHERE ps.project_id = $1
    ORDER BY ps.invited_at DESC
  `, [projectId]);
  return result.rows;
};

const getSharedProjects = async (userId, email) => {
  const result = await pool.query(`
    SELECT p.*, ps.permission, ps.accepted_at as share_accepted_at,
           u.name as owner_name, u.email as owner_email, u.company as owner_company,
           COUNT(DISTINCT s.id) as session_count, COUNT(DISTINCT f.id) as file_count
    FROM project_shares ps
    JOIN projects p ON p.id = ps.project_id
    JOIN users u ON u.id = p.user_id
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE (ps.user_id = $1 OR ps.email = $2) AND (p.status IS NULL OR p.status != 'archived')
    GROUP BY p.id, ps.permission, ps.accepted_at, u.name, u.email, u.company
    ORDER BY p.updated_at DESC
  `, [userId, email]);
  return result.rows;
};

const updateSharePermission = async (shareId, permission) => {
  const result = await pool.query('UPDATE project_shares SET permission = $1 WHERE id = $2', [permission, shareId]);
  return { changes: result.rowCount };
};

const removeShare = async (shareId) => {
  const result = await pool.query('DELETE FROM project_shares WHERE id = $1', [shareId]);
  return { changes: result.rowCount };
};

const acceptShare = async (shareId, userId) => {
  const result = await pool.query('UPDATE project_shares SET user_id = $1, accepted_at = NOW() WHERE id = $2', [userId, shareId]);
  return { changes: result.rowCount };
};

const getShareByProjectAndUser = async (projectId, userId) => {
  const result = await pool.query('SELECT * FROM project_shares WHERE project_id = $1 AND user_id = $2', [projectId, userId]);
  return result.rows[0];
};

const getShareByProjectAndEmail = async (projectId, email) => {
  const result = await pool.query('SELECT * FROM project_shares WHERE project_id = $1 AND email = $2', [projectId, email]);
  return result.rows[0];
};

const getShareById = async (shareId) => {
  const result = await pool.query('SELECT * FROM project_shares WHERE id = $1', [shareId]);
  return result.rows[0];
};

const linkPendingShares = async (userId, email) => {
  const result = await pool.query(
    'UPDATE project_shares SET user_id = $1, accepted_at = NOW() WHERE email = $2 AND user_id IS NULL',
    [userId, email]
  );
  return { changes: result.rowCount };
};

const getShareByToken = async (token) => {
  const result = await pool.query('SELECT * FROM project_shares WHERE invite_token = $1', [token]);
  return result.rows[0];
};

// ==================== MFA ====================

const updateUserMfaSecret = async (userId, secret) => {
  await pool.query('UPDATE users SET mfa_secret = $1 WHERE id = $2', [secret, userId]);
};

// ==================== Signup/Approval ====================

const createPendingUser = async (email, name, company, phone, hashedPassword) => {
  const result = await pool.query(`
    INSERT INTO users (email, password_hash, name, company, phone, role, approved)
    VALUES ($1, $2, $3, $4, $5, 'customer', 0) RETURNING *
  `, [email, hashedPassword, name, company, phone]);
  return result.rows[0];
};

const approveUser = async (id) => {
  await pool.query('UPDATE users SET approved = 1 WHERE id = $1', [id]);
};

// ==================== Feature requests ====================

const createFeatureRequest = async (userId, userName, userEmail, text, page) => {
  await pool.query(
    'INSERT INTO feature_requests (user_id, user_name, user_email, text, page) VALUES ($1, $2, $3, $4, $5)',
    [userId, userName, userEmail, text, page]
  );
};

const getAllFeatureRequests = async () => {
  const result = await pool.query('SELECT * FROM feature_requests ORDER BY created_at DESC');
  return result.rows;
};

// ==================== Query helper ====================

const queryOne = async (sql, params) => {
  const result = await pool.query(sql, params);
  return result.rows[0];
};

// ==================== All sessions (admin) ====================

const getAllSessions = async () => {
  const result = await pool.query(`
    SELECT s.*, p.name as project_name, p.id as project_id, u.name as user_name, u.email as user_email,
           (SELECT COUNT(*) FROM files f WHERE f.session_id = s.id) as file_count
    FROM sessions s
    JOIN projects p ON p.id = s.project_id
    JOIN users u ON u.id = p.user_id
    ORDER BY s.updated_at DESC
  `);
  return result.rows;
};

// ==================== Billing operations ====================

const createSubscription = async (userId, projectId, stripeCustomerId, stripeSubscriptionId, planName, monthlyAmount, setupAmount, periodStart, periodEnd) => {
  const result = await pool.query(`
    INSERT INTO subscriptions (user_id, project_id, stripe_customer_id, stripe_subscription_id, plan_name, monthly_amount, setup_amount, current_period_start, current_period_end)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *
  `, [userId, projectId, stripeCustomerId, stripeSubscriptionId, planName, monthlyAmount, setupAmount, periodStart, periodEnd]);
  return result.rows[0];
};

const getSubscriptionByStripeId = async (stripeSubscriptionId) => {
  const result = await pool.query('SELECT * FROM subscriptions WHERE stripe_subscription_id = $1', [stripeSubscriptionId]);
  return result.rows[0];
};

const getSubscriptionsByUser = async (userId) => {
  const result = await pool.query(`
    SELECT s.*, p.name as project_name FROM subscriptions s
    LEFT JOIN projects p ON p.id = s.project_id
    WHERE s.user_id = $1 ORDER BY s.created_at DESC
  `, [userId]);
  return result.rows;
};

const getSubscriptionsByProject = async (projectId) => {
  const result = await pool.query('SELECT * FROM subscriptions WHERE project_id = $1 ORDER BY created_at DESC', [projectId]);
  return result.rows;
};

const getAllSubscriptions = async () => {
  const result = await pool.query(`
    SELECT s.*, u.name as user_name, u.email as user_email, u.company, p.name as project_name
    FROM subscriptions s
    JOIN users u ON u.id = s.user_id
    LEFT JOIN projects p ON p.id = s.project_id
    ORDER BY s.created_at DESC
  `);
  return result.rows;
};

const updateSubscriptionStatus = async (id, status) => {
  await pool.query('UPDATE subscriptions SET status = $1, updated_at = NOW() WHERE id = $2', [status, id]);
};

const updateSubscriptionPeriod = async (id, periodStart, periodEnd) => {
  await pool.query('UPDATE subscriptions SET current_period_start = $1, current_period_end = $2, updated_at = NOW() WHERE id = $3', [periodStart, periodEnd, id]);
};

const createBillingEvent = async (subscriptionId, stripeEventId, eventType, status, amount, failureReason, attemptCount, rawEvent) => {
  const result = await pool.query(`
    INSERT INTO billing_events (subscription_id, stripe_event_id, event_type, status, amount, failure_reason, attempt_count, raw_event)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *
  `, [subscriptionId, stripeEventId, eventType, status, amount, failureReason, attemptCount, rawEvent ? JSON.stringify(rawEvent) : null]);
  return result.rows[0];
};

const getBillingEventsBySubscription = async (subscriptionId) => {
  const result = await pool.query('SELECT * FROM billing_events WHERE subscription_id = $1 ORDER BY created_at DESC', [subscriptionId]);
  return result.rows;
};

const getPaymentWarnings = async (subscriptionId) => {
  const result = await pool.query('SELECT * FROM payment_warnings WHERE subscription_id = $1 ORDER BY sent_at DESC', [subscriptionId]);
  return result.rows;
};

const createPaymentWarning = async (subscriptionId, warningType, emailTo) => {
  await pool.query('INSERT INTO payment_warnings (subscription_id, warning_type, email_to) VALUES ($1, $2, $3)', [subscriptionId, warningType, emailTo]);
};

const getBillingOverview = async () => {
  const activeResult = await pool.query("SELECT COUNT(*) as count, COALESCE(SUM(monthly_amount), 0) as mrr FROM subscriptions WHERE status = 'active'");
  const pastDueResult = await pool.query("SELECT COUNT(*) as count FROM subscriptions WHERE status = 'past_due'");
  const pausedResult = await pool.query("SELECT COUNT(*) as count FROM subscriptions WHERE status = 'paused'");
  const totalRevenueResult = await pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM billing_events WHERE status = 'succeeded'");
  return {
    activeCount: parseInt(activeResult.rows[0].count),
    mrr: parseInt(activeResult.rows[0].mrr),
    pastDueCount: parseInt(pastDueResult.rows[0].count),
    pausedCount: parseInt(pausedResult.rows[0].count),
    totalRevenue: parseInt(totalRevenueResult.rows[0].total)
  };
};

// ==================== Init ====================

const ready = initDB().catch(err => { 
  console.error('❌ PostgreSQL init failed:', err.message);
  console.error('Retrying in 5 seconds...');
  return new Promise(r => setTimeout(r, 5000)).then(() => initDB(3));
}).catch(err => {
  console.error('❌ PostgreSQL init failed permanently:', err.message);
  process.exit(1);
});

module.exports = {
  ready,
  pool,
  // Users
  getUser,
  getUserById,
  createUser,
  getAllUsers,
  updateUser,
  updateUserPassword,
  deleteUser,
  // Projects
  createProject,
  getProjectsByUser,
  getArchivedProjectsByUser,
  getAllProjects,
  getAllArchivedProjects,
  getProject,
  updateProject,
  updateProjectDesignQuestions,
  updateProjectAdminNotes,
  deleteProject,
  // Sessions
  createSession,
  getSessionsByProject,
  getSession,
  updateSession,
  getLatestSessionForProject,
  appendSessionMessage,
  appendSessionMessageSafe,
  // Files
  createFile,
  getFileById,
  getFilesByProject,
  getFilesBySession,
  getFile,
  deleteFile,
  updateFileDescription,
  // Audit
  logAction,
  // MFA
  updateUserMfaSecret,
  // Signup/Approval
  createPendingUser,
  approveUser,
  // Feature requests
  createFeatureRequest,
  getAllFeatureRequests,
  // Query helper
  queryOne,
  // All sessions (admin)
  getAllSessions,
  // Stats
  getStats,
  // Sharing
  shareProject,
  getProjectShares,
  getSharedProjects,
  updateSharePermission,
  removeShare,
  acceptShare,
  getShareByProjectAndUser,
  getShareByProjectAndEmail,
  getShareById,
  linkPendingShares,
  getShareByToken,
  // Billing
  createSubscription,
  getSubscriptionByStripeId,
  getSubscriptionsByUser,
  getSubscriptionsByProject,
  getAllSubscriptions,
  updateSubscriptionStatus,
  updateSubscriptionPeriod,
  createBillingEvent,
  getBillingEventsBySubscription,
  getPaymentWarnings,
  createPaymentWarning,
  getBillingOverview,
};
