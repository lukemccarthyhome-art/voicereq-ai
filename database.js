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

  // Add description column if it doesn't exist (for existing databases)
  try {
    db.exec(`ALTER TABLE files ADD COLUMN description TEXT`);
    console.log('✅ Added description column to files table');
  } catch (e) {
    // Column already exists, ignore error
  }

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
  return Promise.resolve(db.prepare(`SELECT id, email, name, company, role, created_at FROM users WHERE role = 'customer' ORDER BY created_at DESC`).all());
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
    WHERE p.user_id = ?
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
  // Delete sessions and files first
  db.prepare('DELETE FROM files WHERE project_id = ?').run(id);
  db.prepare('DELETE FROM sessions WHERE project_id = ?').run(id);
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

// Add project.design_questions column if missing
try {
  db.exec(`ALTER TABLE projects ADD COLUMN design_questions TEXT`);
  console.log('✅ Added design_questions column to projects table');
} catch (e) {}


module.exports = {
  ready: Promise.resolve(),
  db,
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
  updateProjectDesignQuestions: (id, json) => {
    const stmt = db.prepare('UPDATE projects SET design_questions = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
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
  getFilesByProject,
  getFilesBySession,
  getFile,
  deleteFile,
  updateFileDescription,
  logAction,
  // Stats
  getStats
};