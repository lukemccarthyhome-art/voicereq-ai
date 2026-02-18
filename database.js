const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

// Use persistent storage path if available (Render disk), fallback to local
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'voicereq.db'));
db.pragma('journal_mode = WAL');

// Create tables
const initDB = () => {
  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      company TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Projects table
  db.exec(`
    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      status TEXT DEFAULT 'active' CHECK (status IN ('active', 'completed', 'archived')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Sessions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL,
      transcript TEXT,
      requirements TEXT,
      context TEXT,
      status TEXT DEFAULT 'active' CHECK (status IN ('active', 'paused', 'completed')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (project_id) REFERENCES projects (id)
    )
  `);

  // Files table
  db.exec(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL,
      session_id INTEGER,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT,
      size INTEGER,
      extracted_text TEXT,
      analysis TEXT,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (project_id) REFERENCES projects (id),
      FOREIGN KEY (session_id) REFERENCES sessions (id)
    )
  `);

  // Feature requests table
  db.exec(`
    CREATE TABLE IF NOT EXISTS feature_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      user_name TEXT,
      user_email TEXT,
      text TEXT NOT NULL,
      page TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Add description column if it doesn't exist (for existing databases)
  try {
    db.exec(`ALTER TABLE files ADD COLUMN description TEXT`);
    console.log('✅ Added description column to files table');
  } catch (e) {
    // Column already exists, ignore error
  }

  // Add phone column if it doesn't exist
  try { db.exec(`ALTER TABLE users ADD COLUMN phone TEXT`); } catch (e) {}
  // Add approved column if it doesn't exist (0 = pending, 1 = approved)
  try { db.exec(`ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 1`); } catch (e) {}

  // Feature requests table
  db.exec(`
    CREATE TABLE IF NOT EXISTS feature_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      user_name TEXT,
      user_email TEXT,
      text TEXT NOT NULL,
      page TEXT,
      status TEXT DEFAULT 'new',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create seed admin user
  createSeedUser();

  console.log('✅ Database initialized');
};

const createSeedUser = () => {
  const existingAdmin = db.prepare('SELECT * FROM users WHERE email = ?').get('luke@voicereq.ai');
  if (!existingAdmin) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    const stmt = db.prepare(`
      INSERT INTO users (email, password_hash, name, company, role)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run('luke@voicereq.ai', hashedPassword, 'Luke McCarthy', 'Morti Projects', 'admin');
    console.log('✅ Seed admin user created: luke@voicereq.ai / admin123');
  }
};

// User operations
const getUser = (email) => {
  return Promise.resolve(db.prepare('SELECT * FROM users WHERE email = ?').get(email));
};

const getUserById = (id) => {
  return Promise.resolve(db.prepare('SELECT * FROM users WHERE id = ?').get(id));
};

const createUser = (email, name, company, role, plainPassword) => {
  const hashedPassword = bcrypt.hashSync(plainPassword, 10);
  const stmt = db.prepare(`
    INSERT INTO users (email, password_hash, name, company, role)
    VALUES (?, ?, ?, ?, ?)
  `);
  return Promise.resolve(stmt.run(email, hashedPassword, name, company, role));
};

const getAllUsers = () => {
  return Promise.resolve(db.prepare(`SELECT id, email, name, company, phone, role, approved, created_at FROM users WHERE role = 'customer' ORDER BY created_at DESC`).all());
};

const updateUser = (id, email, name, company) => {
  const stmt = db.prepare('UPDATE users SET email = ?, name = ?, company = ? WHERE id = ?');
  return Promise.resolve(stmt.run(email, name, company, id));
};

const updateUserPassword = (id, hashedPassword) => {
  const stmt = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
  return Promise.resolve(stmt.run(hashedPassword, id));
};

const deleteUser = (id) => {
  // Delete user's projects, sessions, and files first (cascade)
  const projects = db.prepare('SELECT id FROM projects WHERE user_id = ?').all(id);
  for (const project of projects) {
    deleteProject(project.id);
  }
  return Promise.resolve(db.prepare('DELETE FROM users WHERE id = ?').run(id));
};

// Project operations
const createProject = (userId, name, description) => {
  const stmt = db.prepare(`
    INSERT INTO projects (user_id, name, description)
    VALUES (?, ?, ?)
  `);
  return Promise.resolve(stmt.run(userId, name, description || ''));
};

const getProjectsByUser = (userId) => {
  return Promise.resolve(db.prepare(`
    SELECT p.*, COUNT(s.id) as session_count, COUNT(f.id) as file_count
    FROM projects p
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE p.user_id = ? AND (p.status IS NULL OR p.status != 'archived')
    GROUP BY p.id
    ORDER BY p.updated_at DESC
  `).all(userId));
};

const getArchivedProjectsByUser = (userId) => {
  return Promise.resolve(db.prepare(`
    SELECT p.*, COUNT(s.id) as session_count, COUNT(f.id) as file_count
    FROM projects p
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE p.user_id = ? AND p.status = 'archived'
    GROUP BY p.id
    ORDER BY p.updated_at DESC
  `).all(userId));
};

const getAllProjects = () => {
  return Promise.resolve(db.prepare(`
    SELECT p.*, u.name as user_name, u.company, u.email,
           COUNT(s.id) as session_count, COUNT(f.id) as file_count
    FROM projects p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE (p.status IS NULL OR p.status != 'archived')
    GROUP BY p.id
    ORDER BY p.updated_at DESC
  `).all());
};

const getAllArchivedProjects = () => {
  return Promise.resolve(db.prepare(`
    SELECT p.*, u.name as user_name, u.company, u.email,
           COUNT(s.id) as session_count, COUNT(f.id) as file_count
    FROM projects p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE p.status = 'archived'
    GROUP BY p.id
    ORDER BY p.updated_at DESC
  `).all());
};

const getProject = (id) => {
  return Promise.resolve(db.prepare(`
    SELECT p.*, u.name as user_name, u.company, u.email
    FROM projects p
    JOIN users u ON u.id = p.user_id
    WHERE p.id = ?
  `).get(id));
};

const updateProject = (id, name, description, status) => {
  const stmt = db.prepare(`
    UPDATE projects 
    SET name = ?, description = ?, status = ?, updated_at = CURRENT_TIMESTAMP 
    WHERE id = ?
  `);
  return Promise.resolve(stmt.run(name, description, status, id));
};

const deleteProject = (id) => {
  // Delete sessions, files, and shares first
  db.prepare('DELETE FROM files WHERE project_id = ?').run(id);
  db.prepare('DELETE FROM sessions WHERE project_id = ?').run(id);
  try { db.prepare('DELETE FROM project_shares WHERE project_id = ?').run(id); } catch(e) {}
  return Promise.resolve(db.prepare('DELETE FROM projects WHERE id = ?').run(id));
};

// Session operations
const createSession = (projectId) => {
  const stmt = db.prepare(`
    INSERT INTO sessions (project_id, transcript, requirements, context)
    VALUES (?, ?, ?, ?)
  `);
  return Promise.resolve(stmt.run(projectId, '[]', '{}', '{}'));
};

const getSessionsByProject = (projectId) => {
  return Promise.resolve(db.prepare(`
    SELECT s.*, COUNT(f.id) as file_count
    FROM sessions s
    LEFT JOIN files f ON f.session_id = s.id
    WHERE s.project_id = ?
    GROUP BY s.id
    ORDER BY s.created_at DESC
  `).all(projectId));
};

const getSession = (id) => {
  return Promise.resolve(db.prepare('SELECT * FROM sessions WHERE id = ?').get(id));
};

const updateSession = (id, transcript, requirements, context, status) => {
  const stmt = db.prepare(`
    UPDATE sessions 
    SET transcript = ?, requirements = ?, context = ?, status = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `);
  return Promise.resolve(stmt.run(
    JSON.stringify(transcript), 
    JSON.stringify(requirements), 
    JSON.stringify(context), 
    status, 
    id
  ));
};

const getLatestSessionForProject = (projectId) => {
  return Promise.resolve(db.prepare(`
    SELECT * FROM sessions 
    WHERE project_id = ? AND status != 'completed'
    ORDER BY updated_at DESC 
    LIMIT 1
  `).get(projectId));
};

// Append a message to a session transcript, creating a session if needed
const appendSessionMessage = async (sessionId, message) => {
  if (sessionId) {
    const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);
    if (!s) throw new Error('session not found');
    let transcript = [];
    try { transcript = JSON.parse(s.transcript || '[]'); } catch { transcript = []; }
    transcript.push(message);
    db.prepare('UPDATE sessions SET transcript = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(JSON.stringify(transcript), sessionId);
    return sessionId;
  } else {
    throw new Error('sessionId required');
  }
};

// Safe append: find or create latest session for project, then append
const appendSessionMessageSafe = async (projectId, message) => {
  let session = db.prepare(`SELECT * FROM sessions WHERE project_id = ? AND status != 'completed' ORDER BY updated_at DESC LIMIT 1`).get(projectId);
  if (!session) {
    const res = db.prepare('INSERT INTO sessions (project_id, transcript, requirements, context) VALUES (?, ?, ?, ?)').run(projectId, JSON.stringify([message]), JSON.stringify({}), JSON.stringify({}));
    return res.lastInsertRowid;
  } else {
    const transcript = JSON.parse(session.transcript || '[]');
    transcript.push(message);
    db.prepare('UPDATE sessions SET transcript = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(JSON.stringify(transcript), session.id);
    return session.id;
  }
};

// File operations
const createFile = (projectId, sessionId, filename, originalName, mimeType, size, extractedText, analysis) => {
  const stmt = db.prepare(`
    INSERT INTO files (project_id, session_id, filename, original_name, mime_type, size, extracted_text, analysis)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  return Promise.resolve(stmt.run(projectId, sessionId, filename, originalName, mimeType, size, extractedText, analysis ? JSON.stringify(analysis) : null));
};

const getFileById = (id) => {
  return Promise.resolve(db.prepare('SELECT * FROM files WHERE id = ?').get(id));
};

const getFilesByProject = (projectId) => {
  return Promise.resolve(db.prepare(`
    SELECT f.*, s.status as session_status
    FROM files f
    LEFT JOIN sessions s ON s.id = f.session_id
    WHERE f.project_id = ?
    ORDER BY f.created_at DESC
  `).all(projectId));
};

const getFilesBySession = (sessionId) => {
  return Promise.resolve(db.prepare('SELECT * FROM files WHERE session_id = ? ORDER BY created_at DESC').all(sessionId));
};

const getFile = (fileId) => {
  return Promise.resolve(db.prepare('SELECT * FROM files WHERE id = ?').get(fileId));
};

const deleteFile = (fileId) => {
  return Promise.resolve(db.prepare('DELETE FROM files WHERE id = ?').run(fileId));
};

const updateFileDescription = (fileId, description) => {
  const stmt = db.prepare('UPDATE files SET description = ? WHERE id = ?');
  return Promise.resolve(stmt.run(description, fileId));
};

const logAction = (userId, action, details, ipAddress) => {
  try {
    const stmt = db.prepare('INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)');
    return Promise.resolve(stmt.run(userId, action, JSON.stringify(details), ipAddress));
  } catch (e) {
    return Promise.resolve();
  }
};

// Stats for admin dashboard
const getStats = () => {
  const totalUsers = db.prepare(`SELECT COUNT(*) as count FROM users WHERE role = 'customer'`).get().count;
  const totalProjects = db.prepare('SELECT COUNT(*) as count FROM projects').get().count;
  const totalSessions = db.prepare('SELECT COUNT(*) as count FROM sessions').get().count;
  const companies = db.prepare(`SELECT DISTINCT company FROM users WHERE role = 'customer'`).all().length;
  
  return Promise.resolve({
    totalUsers,
    totalProjects,
    totalSessions,
    totalCompanies: companies
  });
};

// Initialize database on startup
initDB();

// Project shares table
db.exec(`
  CREATE TABLE IF NOT EXISTS project_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    user_id INTEGER,
    email TEXT NOT NULL,
    permission TEXT NOT NULL DEFAULT 'readonly' CHECK (permission IN ('admin', 'user', 'readonly')),
    invited_by INTEGER NOT NULL,
    invited_at TEXT DEFAULT CURRENT_TIMESTAMP,
    accepted_at TEXT,
    invite_token TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (invited_by) REFERENCES users(id)
  )
`);

// Add project.design_questions column if missing
try {
  db.exec(`ALTER TABLE projects ADD COLUMN design_questions TEXT`);
  console.log('✅ Added design_questions column to projects table');
} catch (e) {}

// Add project.admin_notes column if missing
try {
  db.exec(`ALTER TABLE projects ADD COLUMN admin_notes TEXT DEFAULT '[]'`);
  console.log('✅ Added admin_notes column to projects table');
} catch (e) {}


// === Project Sharing Functions ===
const shareProject = (projectId, email, permission, invitedBy, inviteToken) => {
  // Check for duplicate
  const existing = db.prepare('SELECT id FROM project_shares WHERE project_id = ? AND email = ?').get(projectId, email);
  if (existing) throw new Error('Already shared with this email');
  // Check share limit
  const count = db.prepare('SELECT COUNT(*) as c FROM project_shares WHERE project_id = ?').get(projectId).c;
  if (count >= 20) throw new Error('Maximum 20 shares per project');
  // Check if email matches existing user
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  const stmt = db.prepare('INSERT INTO project_shares (project_id, user_id, email, permission, invited_by, invite_token) VALUES (?, ?, ?, ?, ?, ?)');
  const result = stmt.run(projectId, user ? user.id : null, email, permission, invitedBy, inviteToken || null);
  return Promise.resolve(result);
};

const getProjectShares = (projectId) => {
  return Promise.resolve(db.prepare(`
    SELECT ps.*, u.name as user_name, inv.name as inviter_name
    FROM project_shares ps
    LEFT JOIN users u ON u.id = ps.user_id
    LEFT JOIN users inv ON inv.id = ps.invited_by
    WHERE ps.project_id = ?
    ORDER BY ps.invited_at DESC
  `).all(projectId));
};

const getSharedProjects = (userId, email) => {
  return Promise.resolve(db.prepare(`
    SELECT p.*, ps.permission, ps.accepted_at as share_accepted_at, 
           u.name as owner_name, u.email as owner_email, u.company as owner_company,
           COUNT(s.id) as session_count, COUNT(f.id) as file_count
    FROM project_shares ps
    JOIN projects p ON p.id = ps.project_id
    JOIN users u ON u.id = p.user_id
    LEFT JOIN sessions s ON s.project_id = p.id
    LEFT JOIN files f ON f.project_id = p.id
    WHERE (ps.user_id = ? OR ps.email = ?) AND (p.status IS NULL OR p.status != 'archived')
    GROUP BY p.id
    ORDER BY p.updated_at DESC
  `).all(userId, email));
};

const updateSharePermission = (shareId, permission) => {
  return Promise.resolve(db.prepare('UPDATE project_shares SET permission = ? WHERE id = ?').run(permission, shareId));
};

const removeShare = (shareId) => {
  return Promise.resolve(db.prepare('DELETE FROM project_shares WHERE id = ?').run(shareId));
};

const acceptShare = (shareId, userId) => {
  return Promise.resolve(db.prepare('UPDATE project_shares SET user_id = ?, accepted_at = CURRENT_TIMESTAMP WHERE id = ?').run(userId, shareId));
};

const getShareByProjectAndUser = (projectId, userId) => {
  return Promise.resolve(db.prepare('SELECT * FROM project_shares WHERE project_id = ? AND user_id = ?').get(projectId, userId));
};

const getShareByProjectAndEmail = (projectId, email) => {
  return Promise.resolve(db.prepare('SELECT * FROM project_shares WHERE project_id = ? AND email = ?').get(projectId, email));
};

const getShareById = (shareId) => {
  return Promise.resolve(db.prepare('SELECT * FROM project_shares WHERE id = ?').get(shareId));
};

const linkPendingShares = (userId, email) => {
  return Promise.resolve(db.prepare('UPDATE project_shares SET user_id = ?, accepted_at = CURRENT_TIMESTAMP WHERE email = ? AND user_id IS NULL').run(userId, email));
};

const getShareByToken = (token) => {
  return Promise.resolve(db.prepare('SELECT * FROM project_shares WHERE invite_token = ?').get(token));
};

module.exports = {
  ready: Promise.resolve(),
  db,
  getDb: () => db,
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
  updateProjectDesignQuestions: (id, json) => {
    const stmt = db.prepare('UPDATE projects SET design_questions = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    return Promise.resolve(stmt.run(json, id));
  },
  updateProjectAdminNotes: (id, json) => {
    const stmt = db.prepare('UPDATE projects SET admin_notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    return Promise.resolve(stmt.run(json, id));
  },
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
  getFileById,
  getFilesByProject,
  getFilesBySession,
  getFile,
  deleteFile,
  updateFileDescription,
  logAction,
  // Signup/approval
  createPendingUser: (email, name, company, phone, hashedPassword) => {
    const stmt = db.prepare('INSERT INTO users (email, password_hash, name, company, phone, role, approved) VALUES (?, ?, ?, ?, ?, \'customer\', 0)');
    const result = stmt.run(email, hashedPassword, name, company, phone);
    return Promise.resolve(result);
  },
  approveUser: (id) => {
    db.prepare('UPDATE users SET approved = 1 WHERE id = ?').run(id);
    return Promise.resolve();
  },
  // Feature requests
  createFeatureRequest: (userId, userName, userEmail, text, page) => {
    db.prepare('INSERT INTO feature_requests (user_id, user_name, user_email, text, page) VALUES (?, ?, ?, ?, ?)').run(userId, userName, userEmail, text, page);
    return Promise.resolve();
  },
  getAllFeatureRequests: () => {
    return Promise.resolve(db.prepare('SELECT * FROM feature_requests ORDER BY created_at DESC').all());
  },
  queryOne: (sql, params) => {
    // Convert $1, $2 style to ? for SQLite
    const sqliteSql = sql.replace(/\$\d+/g, '?');
    return Promise.resolve(db.prepare(sqliteSql).get(...params));
  },
  // Sessions (extended)
  appendSessionMessage,
  appendSessionMessageSafe,
  // All sessions (admin)
  getAllSessions: () => {
    return Promise.resolve(db.prepare(`
      SELECT s.*, p.name as project_name, p.id as project_id, u.name as user_name, u.email as user_email,
             (SELECT COUNT(*) FROM files f WHERE f.session_id = s.id) as file_count
      FROM sessions s
      JOIN projects p ON p.id = s.project_id
      JOIN users u ON u.id = p.user_id
      ORDER BY s.updated_at DESC
    `).all());
  },
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
  getShareByToken
};