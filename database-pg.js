const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// PostgreSQL connection pool using DATABASE_URL
// Render internal PG doesn't need SSL; external does
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
    // Users table
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

    // Projects table
    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'active' CHECK (status IN ('active', 'completed', 'archived')),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Sessions table
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

    // Files table
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

    // Audit Logs table
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

    // Create seed admin user
    await createSeedUser();

    // Migrations: Add mfa_secret if missing
    try {
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT');
    } catch (e) {
      // Ignore if column exists
    }

    console.log('✅ PostgreSQL database initialized');
  } finally {
    client.release();
  }
};

const createSeedUser = async () => {
  const existingAdmin = await getUser('luke@voicereq.ai');
  if (!existingAdmin) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    const result = await pool.query(`
      INSERT INTO users (email, password_hash, name, company, role)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id
    `, ['luke@voicereq.ai', hashedPassword, 'Luke McCarthy', 'Morti Projects', 'admin']);
    console.log('✅ Seed admin user created: luke@voicereq.ai / admin123');
  }
};

// User operations
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
    VALUES ($1, $2, $3, $4, $5)
    RETURNING *
  `, [email, hashedPassword, name, company, role]);
  return { lastInsertRowid: result.rows[0].id, changes: 1 };
};

const getAllUsers = async () => {
  const result = await pool.query(`
    SELECT id, email, name, company, role, created_at 
    FROM users WHERE role = 'customer' 
    ORDER BY created_at DESC
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
  // Delete user's projects, sessions, and files first (cascade)
  const projects = await pool.query('SELECT id FROM projects WHERE user_id = $1', [id]);
  for (const project of projects.rows) {
    await deleteProject(project.id);
  }
  await pool.query('DELETE FROM audit_logs WHERE user_id = $1', [id]);
  const result = await pool.query('DELETE FROM users WHERE id = $1', [id]);
  return { changes: result.rowCount };
};

// Project operations
const createProject = async (userId, name, description) => {
  const result = await pool.query(`
    INSERT INTO projects (user_id, name, description)
    VALUES ($1, $2, $3)
    RETURNING *
  `, [userId, name, description || '']);
  return { lastInsertRowid: result.rows[0].id, changes: 1 };
};

const getProjectsByUser = async (userId) => {
  const result = await pool.query(`
    SELECT p.*, COUNT(s.id) as session_count, COUNT(f.id) as file_count
    FROM projects p
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE p.user_id = $1
    GROUP BY p.id
    ORDER BY p.updated_at DESC
  `, [userId]);
  return result.rows;
};

const getAllProjects = async () => {
  const result = await pool.query(`
    SELECT p.*, u.name as user_name, u.company, u.email,
           COUNT(s.id) as session_count, COUNT(f.id) as file_count
    FROM projects p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
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
    UPDATE projects 
    SET name = $1, description = $2, status = $3, updated_at = NOW() 
    WHERE id = $4
  `, [name, description, status, id]);
  return { changes: result.rowCount };
};

const deleteProject = async (id) => {
  // Delete sessions and files first
  await pool.query('DELETE FROM files WHERE project_id = $1', [id]);
  await pool.query('DELETE FROM sessions WHERE project_id = $1', [id]);
  const result = await pool.query('DELETE FROM projects WHERE id = $1', [id]);
  return { changes: result.rowCount };
};

// Session operations
const createSession = async (projectId) => {
  const result = await pool.query(`
    INSERT INTO sessions (project_id, transcript, requirements, context)
    VALUES ($1, $2, $3, $4)
    RETURNING *
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
    UPDATE sessions 
    SET transcript = $1, requirements = $2, context = $3, status = $4, updated_at = NOW()
    WHERE id = $5
  `, [
    JSON.stringify(transcript), 
    JSON.stringify(requirements), 
    JSON.stringify(context), 
    status, 
    id
  ]);
  return { changes: result.rowCount };
};

const getLatestSessionForProject = async (projectId) => {
  const result = await pool.query(`
    SELECT * FROM sessions 
    WHERE project_id = $1 AND status != 'completed'
    ORDER BY updated_at DESC 
    LIMIT 1
  `, [projectId]);
  return result.rows[0];
};

// File operations
const createFile = async (projectId, sessionId, filename, originalName, mimeType, size, extractedText, analysis) => {
  const result = await pool.query(`
    INSERT INTO files (project_id, session_id, filename, original_name, mime_type, size, extracted_text, analysis)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING *
  `, [projectId, sessionId, filename, originalName, mimeType, size, extractedText, analysis ? JSON.stringify(analysis) : null]);
  return { lastInsertRowid: result.rows[0].id, changes: 1 };
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

// Audit logging
const logAction = async (userId, action, details, ipAddress) => {
  try {
    await pool.query(`
      INSERT INTO audit_logs (user_id, action, details, ip_address)
      VALUES ($1, $2, $3, $4)
    `, [userId, action, JSON.stringify(details), ipAddress]);
  } catch (e) {
    console.error('❌ Failed to write audit log:', e.message);
  }
};

// Stats for admin dashboard
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

// Initialize database on startup
const ready = initDB().catch(err => { 
  console.error('❌ PostgreSQL init failed:', err.message);
  console.error('Retrying in 5 seconds...');
  return new Promise(r => setTimeout(r, 5000)).then(() => initDB(3));
}).catch(err => {
  console.error('❌ PostgreSQL init failed permanently:', err.message);
  process.exit(1);
});

const updateUserMfaSecret = async (userId, secret) => {
  await pool.query('UPDATE users SET mfa_secret = $1 WHERE id = $2', [secret, userId]);
};

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
  getAllProjects,
  getProject,
  updateProject,
  deleteProject,
  // Sessions
  createSession,
  getSessionsByProject,
  getSession,
  updateSession,
  getLatestSessionForProject,
  // Files
  createFile,
  getFilesByProject,
  getFilesBySession,
  getFile,
  deleteFile,
  updateFileDescription,
  logAction,
  updateUserMfaSecret,
  // Stats
  getStats
};