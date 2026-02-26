#!/usr/bin/env node
/**
 * Prod-to-Test Migration Tool
 * Migrates customers and projects from production to local environment.
 *
 * Usage: node tools/migrate.js
 *
 * Requires PROD_URL and EXPORT_SECRET in .env (or environment).
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Load .env from project root
const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
    if (!process.env[key]) process.env[key] = val;
  }
}

const PROD_URL = (process.env.PROD_URL || '').replace(/\/$/, '');
const EXPORT_SECRET = process.env.EXPORT_SECRET;

if (!PROD_URL || !EXPORT_SECRET) {
  console.error('\n  Missing required env vars. Set in .env:');
  console.error('    PROD_URL=https://your-prod-server.onrender.com');
  console.error('    EXPORT_SECRET=your-shared-secret\n');
  process.exit(1);
}

// Paths for design/proposal files
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const DESIGNS_DIR = path.join(DATA_DIR, 'designs');
const PROPOSALS_DIR = path.join(DATA_DIR, 'proposals');
fs.mkdirSync(DESIGNS_DIR, { recursive: true });
fs.mkdirSync(PROPOSALS_DIR, { recursive: true });

// ── Readline helper ──────────────────────────────────────────────

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(resolve => rl.question(q, resolve));

// ── Fetch helper ─────────────────────────────────────────────────

async function apiFetch(endpoint) {
  const sep = endpoint.includes('?') ? '&' : '?';
  const url = `${PROD_URL}${endpoint}${sep}secret=${EXPORT_SECRET}`;
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return res.json();
}

// ── Database helpers ─────────────────────────────────────────────
// Use the project's own database-adapter so we write to whatever
// the local environment is configured for (SQLite or PG).

let db;
let isPg;

async function initLocalDb() {
  db = require('../database-adapter');
  isPg = !!process.env.DATABASE_URL;
  if (db.ready) await db.ready;
}

async function localQuery(sql, params = []) {
  if (isPg) {
    // PG: use pool.query with $1, $2, ... placeholders
    const pgSql = sql.replace(/\?/g, (() => { let i = 0; return () => `$${++i}`; })());
    const result = await db.pool.query(pgSql, params);
    return result.rows;
  } else {
    // SQLite: use db.db (the raw better-sqlite3 instance)
    const raw = db.db || db.getDb();
    const stmt = raw.prepare(sql);
    if (sql.trim().toUpperCase().startsWith('SELECT')) {
      return stmt.all(...params);
    }
    stmt.run(...params);
    return [];
  }
}

async function localGet(sql, params = []) {
  const rows = await localQuery(sql, params);
  return rows[0] || null;
}

// ── Migrate customer ─────────────────────────────────────────────

async function migrateCustomer(email) {
  if (!email) {
    email = (await ask('  Customer email: ')).trim().toLowerCase();
    if (!email) { console.log('  Cancelled.'); return null; }
  }

  console.log(`\n  Fetching customer ${email} from prod...`);
  let data;
  try {
    data = await apiFetch(`/api/export/customer?email=${encodeURIComponent(email)}`);
  } catch (e) {
    console.error(`  Error: ${e.message}`);
    return null;
  }

  const u = data.user;
  console.log(`  Found: ${u.name} (${u.email}), role=${u.role}, id=${u.id}`);

  // Check if user already exists locally
  const existing = await localGet('SELECT id, email FROM users WHERE email = ?', [u.email]);
  if (existing) {
    console.log(`  User already exists locally (id=${existing.id}). Skipping insert.`);
    return existing;
  }

  // Check if ID is taken by a different user
  const idConflict = await localGet('SELECT id, email FROM users WHERE id = ?', [u.id]);
  if (idConflict) {
    console.log(`  WARNING: Local user id=${u.id} is taken by ${idConflict.email}.`);
    console.log(`  Cannot preserve prod ID. Skipping.`);
    return null;
  }

  // Insert with original ID
  const cols = ['id', 'email', 'password_hash', 'name', 'company', 'role'];
  const vals = [u.id, u.email, u.password_hash, u.name || '', u.company || '', u.role || 'customer'];

  if (u.phone !== undefined) { cols.push('phone'); vals.push(u.phone); }
  if (u.approved !== undefined) { cols.push('approved'); vals.push(u.approved); }
  if (u.created_at) { cols.push('created_at'); vals.push(u.created_at); }

  const placeholders = cols.map(() => '?').join(', ');
  await localQuery(`INSERT INTO users (${cols.join(', ')}) VALUES (${placeholders})`, vals);

  console.log(`  Inserted user id=${u.id} (${u.email})`);
  return { id: u.id, email: u.email };
}

// ── Migrate project ──────────────────────────────────────────────

async function migrateProject() {
  const email = (await ask('  Customer email: ')).trim().toLowerCase();
  if (!email) { console.log('  Cancelled.'); return; }

  // Check if customer exists locally
  let localUser = await localGet('SELECT id, email FROM users WHERE email = ?', [email]);
  if (!localUser) {
    const yn = await ask('  Customer not in local DB. Migrate them first? [Y/n]: ');
    if (yn.toLowerCase() === 'n') { console.log('  Cancelled.'); return; }
    localUser = await migrateCustomer(email);
    if (!localUser) return;
    console.log('');
  }

  // Fetch project list
  console.log(`  Fetching projects for ${email}...`);
  let data;
  try {
    data = await apiFetch(`/api/export/projects?email=${encodeURIComponent(email)}`);
  } catch (e) {
    console.error(`  Error: ${e.message}`);
    return;
  }

  if (!data.projects || data.projects.length === 0) {
    console.log('  No projects found.');
    return;
  }

  console.log('\n  Available projects:');
  data.projects.forEach((p, i) => {
    console.log(`    ${i + 1}. [${p.id}] ${p.name} (${p.status || 'active'})`);
  });

  const choice = (await ask(`\n  Choose project [1-${data.projects.length}]: `)).trim();
  const idx = parseInt(choice, 10) - 1;
  if (isNaN(idx) || idx < 0 || idx >= data.projects.length) {
    console.log('  Invalid choice.');
    return;
  }

  const chosen = data.projects[idx];
  console.log(`\n  Exporting project ${chosen.id} (${chosen.name})...`);

  let bundle;
  try {
    bundle = await apiFetch(`/api/export/project/${chosen.id}`);
  } catch (e) {
    console.error(`  Error: ${e.message}`);
    return;
  }

  const p = bundle.project;
  const stats = { sessions: 0, files: 0, designs: 0, proposals: 0, shares: 0, skipped: [] };

  // ─── Insert project ───
  const existingProject = await localGet('SELECT id FROM projects WHERE id = ?', [p.id]);
  if (existingProject) {
    console.log(`  Project id=${p.id} already exists locally. Skipping project insert.`);
    stats.skipped.push('project (exists)');
  } else {
    const pCols = ['id', 'user_id', 'name', 'description', 'status'];
    const pVals = [p.id, p.user_id, p.name, p.description || '', p.status || 'active'];
    if (p.created_at) { pCols.push('created_at'); pVals.push(p.created_at); }
    if (p.updated_at) { pCols.push('updated_at'); pVals.push(p.updated_at); }
    if (p.design_questions) { pCols.push('design_questions'); pVals.push(p.design_questions); }
    if (p.admin_notes) { pCols.push('admin_notes'); pVals.push(p.admin_notes); }

    const ph = pCols.map(() => '?').join(', ');
    await localQuery(`INSERT INTO projects (${pCols.join(', ')}) VALUES (${ph})`, pVals);
    console.log(`  Inserted project id=${p.id}`);
  }

  // ─── Insert sessions ───
  for (const s of (bundle.sessions || [])) {
    const existing = await localGet('SELECT id FROM sessions WHERE id = ?', [s.id]);
    if (existing) { stats.skipped.push(`session ${s.id}`); continue; }

    const sCols = ['id', 'project_id', 'transcript', 'requirements', 'context', 'status'];
    const sVals = [s.id, s.project_id, s.transcript || '[]', s.requirements || '{}', s.context || '{}', s.status || 'active'];
    if (s.created_at) { sCols.push('created_at'); sVals.push(s.created_at); }
    if (s.updated_at) { sCols.push('updated_at'); sVals.push(s.updated_at); }

    const ph = sCols.map(() => '?').join(', ');
    await localQuery(`INSERT INTO sessions (${sCols.join(', ')}) VALUES (${ph})`, sVals);
    stats.sessions++;
  }

  // ─── Insert files ───
  for (const f of (bundle.files || [])) {
    const existing = await localGet('SELECT id FROM files WHERE id = ?', [f.id]);
    if (existing) { stats.skipped.push(`file ${f.id}`); continue; }

    const fCols = ['id', 'project_id', 'session_id', 'filename', 'original_name', 'mime_type', 'size', 'extracted_text'];
    const fVals = [f.id, f.project_id, f.session_id, f.filename || '', f.original_name || '', f.mime_type || '', f.size || 0, f.extracted_text || ''];
    if (f.analysis) { fCols.push('analysis'); fVals.push(f.analysis); }
    if (f.description) { fCols.push('description'); fVals.push(f.description); }
    if (f.created_at) { fCols.push('created_at'); fVals.push(f.created_at); }

    const ph = fCols.map(() => '?').join(', ');
    await localQuery(`INSERT INTO files (${fCols.join(', ')}) VALUES (${ph})`, fVals);
    stats.files++;
  }

  // ─── Write design files ───
  for (const d of (bundle.designs || [])) {
    const fp = path.join(DESIGNS_DIR, d.filename);
    fs.writeFileSync(fp, JSON.stringify(d.content, null, 2));
    stats.designs++;
  }

  // ─── Write proposal files ───
  for (const pr of (bundle.proposals || [])) {
    const fp = path.join(PROPOSALS_DIR, pr.filename);
    fs.writeFileSync(fp, JSON.stringify(pr.content, null, 2));
    stats.proposals++;
  }

  // ─── Insert shares ───
  for (const sh of (bundle.shares || [])) {
    try {
      const existing = await localGet('SELECT id FROM project_shares WHERE id = ?', [sh.id]);
      if (existing) { stats.skipped.push(`share ${sh.id}`); continue; }

      const shCols = ['id', 'project_id', 'email', 'permission', 'invited_by'];
      const shVals = [sh.id, sh.project_id, sh.email, sh.permission || 'readonly', sh.invited_by];
      if (sh.user_id) { shCols.push('user_id'); shVals.push(sh.user_id); }
      if (sh.invited_at) { shCols.push('invited_at'); shVals.push(sh.invited_at); }
      if (sh.accepted_at) { shCols.push('accepted_at'); shVals.push(sh.accepted_at); }
      if (sh.invite_token) { shCols.push('invite_token'); shVals.push(sh.invite_token); }

      const ph = shCols.map(() => '?').join(', ');
      await localQuery(`INSERT INTO project_shares (${shCols.join(', ')}) VALUES (${ph})`, shVals);
      stats.shares++;
    } catch (e) {
      stats.skipped.push(`share ${sh.id} (${e.message})`);
    }
  }

  // ─── Summary ───
  console.log('\n  ─── Migration Summary ───');
  console.log(`  Project:   ${p.name} (id=${p.id})`);
  console.log(`  Sessions:  ${stats.sessions} imported`);
  console.log(`  Files:     ${stats.files} imported (metadata only, no binaries)`);
  console.log(`  Designs:   ${stats.designs} written to ${DESIGNS_DIR}`);
  console.log(`  Proposals: ${stats.proposals} written to ${PROPOSALS_DIR}`);
  console.log(`  Shares:    ${stats.shares} imported`);
  if (stats.skipped.length > 0) {
    console.log(`  Skipped:   ${stats.skipped.join(', ')}`);
  }
  console.log('');
}

// ── Main ─────────────────────────────────────────────────────────

async function main() {
  console.log('\n  Morti Migration Tool');
  console.log('  ━━━━━━━━━━━━━━━━━━━');
  console.log(`  Source: ${PROD_URL}`);
  console.log('');

  await initLocalDb();

  console.log('  1. Migrate customer');
  console.log('  2. Migrate project (includes customer if needed)');
  console.log('');
  const choice = (await ask('  Choose [1/2]: ')).trim();

  console.log('');
  if (choice === '1') {
    await migrateCustomer();
  } else if (choice === '2') {
    await migrateProject();
  } else {
    console.log('  Invalid choice.');
  }

  rl.close();
}

main().catch(e => {
  console.error('\n  Fatal error:', e);
  process.exit(1);
});
