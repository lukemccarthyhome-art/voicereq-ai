const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const db = require('../database-adapter');
const auth = require('../auth');
const { DESIGNS_DIR, PROPOSALS_DIR } = require('../helpers/paths');
const { encodeProjectId, resolveProjectId } = require('../helpers/ids');
const { apiAuth } = require('../middleware/auth-middleware');
const { loadNewestDesign, saveDesign } = require('./design');
const { loadNewestProposal } = require('./proposals');
const { uploadsDir } = require('../helpers/paths');

// Decode hashed IDs in :id route params
router.param('id', (req, res, next, val) => {
  req.params.id = resolveProjectId(val);
  next();
});

// === ARCHIVED PROJECTS (admin) ===
router.get('/admin/projects/archived', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const projects = await db.getAllArchivedProjects();
  res.render('admin/projects-archived', {
    user: req.user,
    projects,
    title: 'Archived Projects',
    currentPage: 'admin-projects'
  });
});

// Mark project as complete (customer action from voice session)
router.post('/api/projects/:id/rename', apiAuth, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Not found' });
    if (project.user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Name required' });
    await db.updateProject(req.params.id, name, project.description, project.status);
    await db.logAction(req.user.id, 'rename_project', { projectId: req.params.id, oldName: project.name, newName: name }, req.ip);
    res.json({ ok: true });
  } catch (e) { console.error('Rename error:', e); res.status(500).json({ error: 'Failed' }); }
});

// Background requirements refresh — called after project complete, non-blocking
async function refreshRequirementsInBackground(projectId) {
  const OPENAI_KEY = process.env.OPENAI_API_KEY;
  if (!OPENAI_KEY) return;
  const sessions = await db.getSessionsByProject(projectId);
  if (!sessions || sessions.length === 0) return;
  const session = sessions[0]; // most recent
  let transcript, existingRequirements;
  try { transcript = typeof session.transcript === 'string' ? JSON.parse(session.transcript) : session.transcript; } catch { transcript = []; }
  try { existingRequirements = typeof session.requirements === 'string' ? JSON.parse(session.requirements) : session.requirements; } catch { existingRequirements = {}; }
  if ((!transcript || transcript.length === 0) && (!existingRequirements || Object.keys(existingRequirements).length === 0)) return;

  // Build analysis content (same logic as /api/analyze-session)
  let analysisContent = '';
  if (transcript && transcript.length > 0) {
    analysisContent += '## CONVERSATION TRANSCRIPT\n\n';
    transcript.forEach(msg => {
      const speaker = msg.role === 'ai' ? 'Business Analyst' : 'Client';
      analysisContent += `**${speaker}:** ${msg.text}\n\n`;
    });
  }
  // Load files
  let dbFiles = await db.getFilesBySession(session.id) || [];
  if (dbFiles.length === 0) dbFiles = await db.getFilesByProject(projectId) || [];
  const filesToAnalyze = {};
  for (const file of dbFiles) {
    const fname = file.original_name || file.filename;
    const diskPath = path.join(uploadsDir, fname);
    if (fs.existsSync(diskPath)) {
      try {
        const ext = path.extname(fname).toLowerCase();
        let content = '';
        if (['.txt','.md','.csv','.json','.xml','.yaml','.yml','.html','.css','.js','.ts','.py'].includes(ext)) {
          content = fs.readFileSync(diskPath, 'utf8');
        } else if (['.doc','.docx'].includes(ext)) {
          try { const mammoth = require('mammoth'); const r = await mammoth.extractRawText({ path: diskPath }); content = r.value; } catch { content = file.extracted_text || ''; }
        } else { content = file.extracted_text || ''; }
        if (content) filesToAnalyze[fname] = content.length > 50000 ? content.substring(0, 50000) : content;
      } catch { if (file.extracted_text) filesToAnalyze[fname] = file.extracted_text; }
    } else if (file.extracted_text) { filesToAnalyze[fname] = file.extracted_text; }
  }
  if (Object.keys(filesToAnalyze).length > 0) {
    analysisContent += '## UPLOADED DOCUMENTS\n\n';
    for (const [filename, content] of Object.entries(filesToAnalyze)) {
      analysisContent += `### ${filename}\n\n${content}\n\n---\n\n`;
    }
  }
  if (existingRequirements && Object.keys(existingRequirements).length > 0) {
    analysisContent += '## ALREADY CAPTURED REQUIREMENTS (DO NOT REPEAT THESE)\n\n';
    for (const [cat, items] of Object.entries(existingRequirements)) {
      if (Array.isArray(items) && items.length > 0) {
        analysisContent += `### ${cat}\n`;
        items.forEach(r => { analysisContent += `- ${typeof r === 'string' ? r : r.text || r}\n`; });
        analysisContent += '\n';
      }
    }
  }
  if (!analysisContent.trim()) return;

  console.log('🔄 Background requirements refresh for project', projectId);
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
    body: JSON.stringify({
      model: process.env.LLM_MODEL || 'gpt-4.1',
      max_completion_tokens: 4096,
      messages: [{
        role: 'system',
        content: `You are an expert business analyst. Analyze the conversation transcript and documents to extract NEW requirements not already captured. PRESERVE SPECIFICITY: include exact numbers, names, tools, platforms. Only return genuinely NEW requirements. Return valid JSON: {"requirements":{"Category":["requirement",...]}}`
      }, { role: 'user', content: analysisContent }],
      response_format: { type: 'json_object' }
    })
  });
  if (!response.ok) { console.error('Background refresh OpenAI error:', await response.text()); return; }
  const data = await response.json();
  const analysis = JSON.parse(data.choices[0].message.content);
  const newReqs = analysis.requirements || {};
  // Merge new requirements into existing
  let merged = { ...existingRequirements };
  for (const [cat, items] of Object.entries(newReqs)) {
    if (!Array.isArray(items) || items.length === 0) continue;
    if (!merged[cat]) { merged[cat] = items; }
    else {
      const existing = new Set(merged[cat].map(r => (typeof r === 'string' ? r : r.text || '').toLowerCase().trim()));
      const additions = items.filter(r => { const t = (typeof r === 'string' ? r : r.text || '').toLowerCase().trim(); return !existing.has(t); });
      if (additions.length > 0) merged[cat] = [...merged[cat], ...additions];
    }
  }
  // Save back to session
  const context = typeof session.context === 'string' ? session.context : JSON.stringify(session.context || {});
  await db.updateSession(session.id, JSON.stringify(transcript), JSON.stringify(merged), context, session.status || 'paused');
  const totalNew = Object.values(newReqs).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0);
  console.log('✅ Background refresh done for project', projectId, '—', totalNew, 'new requirements');
}

router.post('/api/projects/:id/complete', apiAuth, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    // Verify ownership (admin or owner)
    if (req.user.role !== 'admin' && project.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    // Update project status to completed and set design_review_requested
    await db.updateProject(projectId, project.name, project.description, 'completed');
    // Set design_review_requested timestamp (uses a simple column add if not exists)
    try {
      await db.pool.query('UPDATE projects SET design_review_requested = NOW() WHERE id = $1', [projectId]);
    } catch (e) {
      // Column might not exist yet — add it
      try {
        await db.pool.query('ALTER TABLE projects ADD COLUMN IF NOT EXISTS design_review_requested TIMESTAMP');
        await db.pool.query('UPDATE projects SET design_review_requested = NOW() WHERE id = $1', [projectId]);
      } catch (e2) { console.warn('Could not set design_review_requested:', e2.message); }
    }
    await db.logAction(req.user.id, 'project_completed', { projectId, projectName: project.name }, req.ip);
    // Notify admin via Telegram
    const tgToken = process.env.TELEGRAM_BOT_TOKEN;
    const tgChat = process.env.TELEGRAM_CHAT_ID;
    if (tgToken && tgChat) {
      const msg = `✅ Project Completed & Ready for Design Review\nProject: ${project.name}\nBy: ${req.user.name} (${req.user.email})\nTime: ${new Date().toLocaleString('en-AU', { timeZone: 'Australia/Melbourne' })}`;
      fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: tgChat, text: msg })
      }).catch(err => console.error('Telegram notify failed:', err.message));
    }
    res.json({ success: true });
    // Background: refresh requirements via LLM analysis (non-blocking)
    refreshRequirementsInBackground(projectId).catch(err =>
      console.error('Background requirements refresh failed:', err.message)
    );
  } catch (e) {
    console.error('Complete project error:', e);
    res.status(500).json({ error: 'Failed to complete project' });
  }
});

// Archive/Unarchive project (admin)
router.post('/admin/projects/:id/archive', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    await db.updateProject(req.params.id, project.name, project.description, 'archived');
    res.redirect('/admin/projects?message=Project+archived');
  } catch (e) {
    console.error('Archive error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}?error=Archive+failed`);
  }
});

router.post('/admin/projects/:id/unarchive', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    await db.updateProject(req.params.id, project.name, project.description, 'active');
    res.redirect('/admin/projects/archived?message=Project+unarchived');
  } catch (e) {
    console.error('Unarchive error:', e);
    res.redirect('/admin/projects/archived?error=Unarchive+failed');
  }
});

// Requirements page (admin)
router.get('/admin/projects/:id/requirements', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    const sessions = await db.getSessionsByProject(req.params.id);
    const allRequirements = {};
    sessions.forEach(s => {
      try {
        const reqs = JSON.parse(s.requirements || '{}');
        for (const [cat, items] of Object.entries(reqs)) {
          if (!allRequirements[cat]) allRequirements[cat] = [];
          if (Array.isArray(items)) allRequirements[cat] = allRequirements[cat].concat(items);
        }
      } catch {}
    });
    res.render('admin/project-requirements', { user: req.user, project, requirements: allRequirements, title: project.name + ' - Requirements', currentPage: 'admin-projects' });
  } catch (e) {
    console.error('Requirements error:', e);
    res.status(500).send('Failed to load requirements');
  }
});

router.get('/admin/projects', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const projects = await db.getAllProjects();
  res.render('admin/projects', {
    user: req.user,
    projects,
    title: 'All Projects',
    currentPage: 'admin-projects',
    breadcrumbs: [
      { name: 'Dashboard', url: '/admin' },
      { name: 'Projects' }
    ]
  });
});

router.get('/admin/projects/:id', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) {
    return res.status(404).send('Project not found');
  }

  const sessions = await db.getSessionsByProject(req.params.id);
  const files = await db.getFilesByProject(req.params.id);

  // check for existing design
  const designsDir = DESIGNS_DIR;
  let designExists = false;
  try {
    if (fs.existsSync(designsDir)) {
      const files = fs.readdirSync(designsDir).filter(f => f.startsWith(`design-${req.params.id}-`));
      if (files.length > 0) {
        designExists = true;
        // build designs list with metadata
        const designsList = files.map(fn => {
          try { const d = JSON.parse(fs.readFileSync(path.join(designsDir, fn), 'utf8')); return { id: d.id || fn.replace('.json',''), file: fn, createdAt: d.createdAt || fs.statSync(path.join(designsDir, fn)).mtime.toISOString(), version: d.version || 1, status: d.status || 'draft', owner: d.owner || '' }; } catch(e) { return { id: fn.replace('.json',''), file: fn, createdAt: fs.statSync(path.join(designsDir, fn)).mtime.toISOString(), version: 1, status: 'draft', owner: '' }; }
        }).sort((a,b)=> new Date(b.createdAt)-new Date(a.createdAt));
        // attach to locals
        res.locals.designsList = designsList;
        try {
          const newestFile = designsList[0] && designsList[0].file;
          if (newestFile) {
            const newestDesign = JSON.parse(fs.readFileSync(path.join(designsDir, newestFile), "utf8"));
            res.locals.latestDesign = newestDesign;
          }
        } catch(e) {}
      }
    }
  } catch(e) { designExists = false; }
  // Get customer answers from latest design
  let customerAnswers = [];
  try {
    const designResult = loadNewestDesign(req.params.id);
    if (designResult && designResult.design && designResult.design.customerAnswers) {
      customerAnswers = designResult.design.customerAnswers;
    }
  } catch(e) {}

  // Compute design/proposal status for milestone tracker
  let hasDesignPublished = false, hasDesignApproved = false;
  let hasProposalPublished = false, hasProposalApproved = false;
  try {
    const designResult = loadNewestDesign(req.params.id);
    if (designResult && designResult.design) {
      hasDesignPublished = !!designResult.design.published;
      hasDesignApproved = !!designResult.design.approvedAt;
    }
  } catch {}
  try {
    const prop = loadNewestProposal(req.params.id);
    if (prop) {
      hasProposalPublished = !!prop.published;
      hasProposalApproved = !!prop.approvedAt;
    }
  } catch {}
  const hasReqs = sessions.some(s => {
    try { const r = JSON.parse(s.requirements || '{}'); return Object.values(r).some(a => Array.isArray(a) && a.length > 0); } catch { return false; }
  });

  res.render('admin/project-detail', {
    customerAnswers,
    designExists: designExists,
    hasDesignPublished,
    hasDesignApproved,
    hasProposalPublished,
    hasProposalApproved,
    hasReqs,
    user: req.user,
    project,
    sessions,
    files,
    title: project.name + ' - Project Detail',
    currentPage: 'admin-projects',
    breadcrumbs: [
      { name: 'Dashboard', url: '/admin' },
      { name: 'Projects', url: '/admin/projects' },
      { name: project.name }
    ]
  });
});

// === MIGRATE WEB UI (admin) ===

const PROD_URL = (process.env.PROD_URL || '').replace(/\/$/, '');
const EXPORT_SECRET = process.env.EXPORT_SECRET || '';

// Helper: fetch from prod export API
async function prodFetch(endpoint) {
  if (!PROD_URL || !EXPORT_SECRET) throw new Error('PROD_URL and EXPORT_SECRET must be set in .env');
  const sep = endpoint.includes('?') ? '&' : '?';
  const url = `${PROD_URL}${endpoint}${sep}secret=${EXPORT_SECRET}`;
  const res = await fetch(url);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json();
}

// Helper: raw SQL query against local DB (preserves IDs)
const isPg = !!process.env.DATABASE_URL;
async function localQuery(sql, params = []) {
  if (isPg) {
    const pgSql = sql.replace(/\?/g, (() => { let i = 0; return () => `$${++i}`; })());
    const result = await db.pool.query(pgSql, params);
    return result.rows;
  } else {
    const raw = db.db || db.getDb();
    const stmt = raw.prepare(sql);
    if (sql.trim().toUpperCase().startsWith('SELECT')) return stmt.all(...params);
    stmt.run(...params);
    return [];
  }
}
async function localGet(sql, params = []) {
  const rows = await localQuery(sql, params);
  return rows[0] || null;
}

// Page
router.get('/admin/migrate', auth.authenticate, auth.requireAdmin, (req, res) => {
  const configured = !!(PROD_URL && EXPORT_SECRET);
  res.render('admin/migrate', { user: req.user, title: 'Migrate from Prod', currentPage: 'migrate', configured });
});

// Look up customer on prod
router.post('/admin/migrate/customer', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const data = await prodFetch(`/api/export/customer?email=${encodeURIComponent(email)}`);
    res.json({ ok: true, user: data.user });
  } catch (e) {
    console.error('Migrate customer lookup error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Import customer into local DB
router.post('/admin/migrate/customer/import', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const data = await prodFetch(`/api/export/customer?email=${encodeURIComponent(email)}`);
    const u = data.user;

    // Check if already exists
    const existing = await localGet('SELECT id, email FROM users WHERE email = ?', [u.email]);
    if (existing) return res.json({ ok: true, message: 'User already exists locally', user: existing, alreadyExisted: true });

    // Check ID conflict
    const idConflict = await localGet('SELECT id, email FROM users WHERE id = ?', [u.id]);
    if (idConflict) return res.status(409).json({ error: `Local user id=${u.id} is taken by ${idConflict.email}. Cannot preserve prod ID.` });

    // Insert
    const cols = ['id', 'email', 'password_hash', 'name', 'company', 'role'];
    const vals = [u.id, u.email, u.password_hash, u.name || '', u.company || '', u.role || 'customer'];
    if (u.phone !== undefined) { cols.push('phone'); vals.push(u.phone); }
    if (u.approved !== undefined) { cols.push('approved'); vals.push(u.approved); }
    if (u.created_at) { cols.push('created_at'); vals.push(u.created_at); }
    const placeholders = cols.map(() => '?').join(', ');
    await localQuery(`INSERT INTO users (${cols.join(', ')}) VALUES (${placeholders})`, vals);

    res.json({ ok: true, message: `Imported user ${u.email} (id=${u.id})`, user: { id: u.id, email: u.email, name: u.name, company: u.company } });
  } catch (e) {
    console.error('Migrate customer import error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Fetch project list from prod
router.post('/admin/migrate/projects', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const data = await prodFetch(`/api/export/projects?email=${encodeURIComponent(email)}`);
    res.json({ ok: true, projects: data.projects || [] });
  } catch (e) {
    console.error('Migrate projects list error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Import a single project into local DB
router.post('/admin/migrate/project', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.body.projectId;
    if (!projectId) return res.status(400).json({ error: 'projectId required' });

    const bundle = await prodFetch(`/api/export/project/${projectId}`);
    const p = bundle.project;
    const stats = { sessions: 0, files: 0, designs: 0, proposals: 0, shares: 0, skipped: [] };

    // Ensure customer exists locally
    const localUser = await localGet('SELECT id FROM users WHERE id = ?', [p.user_id]);
    if (!localUser && bundle.user) {
      const u = bundle.user;
      const idConflict = await localGet('SELECT id, email FROM users WHERE id = ?', [u.id]);
      if (!idConflict) {
        const cols = ['id', 'email', 'password_hash', 'name', 'company', 'role'];
        const vals = [u.id, u.email, u.password_hash, u.name || '', u.company || '', u.role || 'customer'];
        if (u.phone !== undefined) { cols.push('phone'); vals.push(u.phone); }
        if (u.approved !== undefined) { cols.push('approved'); vals.push(u.approved); }
        if (u.created_at) { cols.push('created_at'); vals.push(u.created_at); }
        const ph = cols.map(() => '?').join(', ');
        await localQuery(`INSERT INTO users (${cols.join(', ')}) VALUES (${ph})`, vals);
        stats.skipped.push('auto-imported customer');
      }
    }

    // Insert project
    const existingProject = await localGet('SELECT id FROM projects WHERE id = ?', [p.id]);
    if (existingProject) {
      stats.skipped.push('project (already exists)');
    } else {
      const pCols = ['id', 'user_id', 'name', 'description', 'status'];
      const pVals = [p.id, p.user_id, p.name, p.description || '', p.status || 'active'];
      if (p.created_at) { pCols.push('created_at'); pVals.push(p.created_at); }
      if (p.updated_at) { pCols.push('updated_at'); pVals.push(p.updated_at); }
      if (p.design_questions) { pCols.push('design_questions'); pVals.push(p.design_questions); }
      if (p.admin_notes) { pCols.push('admin_notes'); pVals.push(p.admin_notes); }
      const ph = pCols.map(() => '?').join(', ');
      await localQuery(`INSERT INTO projects (${pCols.join(', ')}) VALUES (${ph})`, pVals);
    }

    // Insert sessions
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

    // Insert files
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

    // Write design files
    fs.mkdirSync(DESIGNS_DIR, { recursive: true });
    for (const d of (bundle.designs || [])) {
      fs.writeFileSync(path.join(DESIGNS_DIR, d.filename), JSON.stringify(d.content, null, 2));
      stats.designs++;
    }

    // Write proposal files
    fs.mkdirSync(PROPOSALS_DIR, { recursive: true });
    for (const pr of (bundle.proposals || [])) {
      fs.writeFileSync(path.join(PROPOSALS_DIR, pr.filename), JSON.stringify(pr.content, null, 2));
      stats.proposals++;
    }

    // Insert shares
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

    res.json({
      ok: true,
      summary: {
        project: p.name,
        projectId: p.id,
        sessions: stats.sessions,
        files: stats.files,
        designs: stats.designs,
        proposals: stats.proposals,
        shares: stats.shares,
        skipped: stats.skipped
      }
    });
  } catch (e) {
    console.error('Migrate project import error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// === EXPORT API (for prod-to-test migration) ===
// Protected by EXPORT_SECRET env var, no JWT needed

function requireExportSecret(req, res, next) {
  const secret = process.env.EXPORT_SECRET;
  if (!secret) return res.status(503).json({ error: 'Export not configured' });
  if (req.query.secret !== secret) return res.status(403).json({ error: 'Invalid secret' });
  next();
}

// Export customer by email
router.get('/api/export/customer', requireExportSecret, async (req, res) => {
  try {
    const email = (req.query.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const user = await db.getUser(email);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ type: 'customer', user });
  } catch (e) {
    console.error('Export customer error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

// Export project list for a customer
router.get('/api/export/projects', requireExportSecret, async (req, res) => {
  try {
    const email = (req.query.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const user = await db.getUser(email);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const projects = await db.getProjectsByUser(user.id);
    res.json({
      type: 'project_list',
      projects: projects.map(p => ({ id: p.id, name: p.name, status: p.status, created_at: p.created_at }))
    });
  } catch (e) {
    console.error('Export projects error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

// Export full project bundle by ID
router.get('/api/export/project/:id', requireExportSecret, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const user = await db.getUserById(project.user_id);
    const sessions = await db.getSessionsByProject(projectId);
    const files = await db.getFilesByProject(projectId);
    const shares = await db.getProjectShares(projectId);

    // Read design files from disk
    const designs = [];
    try {
      if (fs.existsSync(DESIGNS_DIR)) {
        const designFiles = fs.readdirSync(DESIGNS_DIR).filter(f => f.startsWith(`design-${projectId}-`));
        for (const fn of designFiles) {
          try {
            const content = JSON.parse(fs.readFileSync(path.join(DESIGNS_DIR, fn), 'utf8'));
            designs.push({ filename: fn, content });
          } catch (e) { console.warn('Could not read design file:', fn, e.message); }
        }
      }
    } catch (e) { console.warn('Design dir read error:', e.message); }

    // Read proposal files from disk
    const proposals = [];
    try {
      if (fs.existsSync(PROPOSALS_DIR)) {
        const proposalFiles = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${projectId}-`));
        for (const fn of proposalFiles) {
          try {
            const content = JSON.parse(fs.readFileSync(path.join(PROPOSALS_DIR, fn), 'utf8'));
            proposals.push({ filename: fn, content });
          } catch (e) { console.warn('Could not read proposal file:', fn, e.message); }
        }
      }
    } catch (e) { console.warn('Proposal dir read error:', e.message); }

    res.json({ type: 'project', project, user, sessions, files, designs, proposals, shares });
  } catch (e) {
    console.error('Export project error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

module.exports = router;
