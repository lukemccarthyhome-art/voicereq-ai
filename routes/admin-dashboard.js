const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const db = require('../database-adapter');
const auth = require('../auth');
const emails = require('../emails');
const { apiAuth, verifyFileOwnership } = require('../middleware/auth-middleware');
const { uploadsDir } = require('../helpers/paths');
const { encodeProjectId, resolveProjectId } = require('../helpers/ids');
const { sendSecurityAlert, sendMortiEmail } = require('../helpers/email-sender');

// Decode hashed IDs in :id route params
router.param('id', (req, res, next, val) => {
  req.params.id = resolveProjectId(val);
  next();
});

// === ADMIN DASHBOARD ===

router.get('/admin', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const stats = await db.getStats();
  const recentCustomers = (await db.getAllUsers()).slice(0, 8);
  const recentProjects = (await db.getAllProjects()).slice(0, 8);

  res.render('admin/dashboard', {
    user: req.user,
    stats,
    recentCustomers,
    recentProjects,
    title: 'Admin Dashboard',
    currentPage: 'admin-dashboard',
    breadcrumbs: [{ name: 'Dashboard' }]
  });
});

// === CUSTOMER MANAGEMENT ===

router.get('/admin/customers', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const customers = await db.getAllUsers();
  res.render('admin/customers', {
    user: req.user,
    customers,
    title: 'Customer Management',
    currentPage: 'admin-customers',
    breadcrumbs: [
      { name: 'Dashboard', url: '/admin' },
      { name: 'Customers' }
    ]
  });
});

router.post('/admin/customers', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { name, email, company, password } = req.body;
    const finalPassword = password || Math.random().toString(36).slice(-8);

    await db.createUser(email, name, company, 'customer', finalPassword);

    // Alert on new customer
    sendSecurityAlert('New Customer Created', {
      name,
      email,
      company,
      createdBy: req.user.email,
      ip: req.ip
    });

    res.redirect('/admin/customers?message=Customer created successfully');
  } catch (e) {
    console.error('Create customer error:', e);
    res.redirect('/admin/customers?error=Failed to create customer');
  }
});

router.post('/admin/customers/:id', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { name, email, company } = req.body;
    await db.updateUser(req.params.id, email, name, company);
    res.redirect('/admin/customers?message=Customer updated successfully');
  } catch (e) {
    console.error('Update customer error:', e);
    res.redirect('/admin/customers?error=Failed to update customer');
  }
});

router.post('/admin/customers/:id/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    await db.deleteUser(req.params.id);
    res.redirect('/admin/customers?message=Customer deleted successfully');
  } catch (e) {
    console.error('Delete customer error:', e);
    res.redirect('/admin/customers?error=Failed to delete customer');
  }
});

// Approve customer account
router.post('/admin/customers/:id/approve', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    // Get user details before approving (for email)
    const user = await db.getUserById(req.params.id);
    await db.approveUser(req.params.id);

    // Send approval email
    if (user && user.email) {
      const approved = emails.accountApprovedEmail(user.name);
      sendMortiEmail(user.email, approved.subject, approved.html).catch(() => {});
    }

    res.redirect('/admin/customers?message=Customer approved successfully');
  } catch (e) {
    console.error('Approve customer error:', e);
    res.redirect('/admin/customers?error=Failed to approve customer');
  }
});

// Admin: Reset customer password
router.post('/admin/customers/:id/password', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 6) {
      return res.redirect(`/admin/customers?error=Password must be at least 6 characters`);
    }

    const hashedPassword = auth.hashPassword(password);
    await db.updateUserPassword(req.params.id, hashedPassword);
    res.redirect('/admin/customers?message=Customer password updated successfully');
  } catch (e) {
    console.error('Update customer password error:', e);
    res.redirect('/admin/customers?error=Failed to update customer password');
  }
});

// === PROJECT MANAGEMENT ===

// Delete project (admin)
router.post('/admin/projects/:id/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    // Delete uploaded files from disk
    const files = await db.getFilesByProject(req.params.id);
    files.forEach(f => {
      const fp = path.join(uploadsDir, f.filename || f.original_name);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    });
    await db.deleteProject(req.params.id);
    res.redirect('/admin/projects?message=Project deleted successfully');
  } catch (e) {
    console.error('Delete project error:', e);
    res.redirect('/admin/projects?error=Failed to delete project');
  }
});

// Delete project (customer)
router.post('/projects/:id/delete', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project || project.user_id !== req.user.id) return res.status(403).send('Forbidden');
    const files = await db.getFilesByProject(req.params.id);
    files.forEach(f => {
      const fp = path.join(uploadsDir, f.filename || f.original_name);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    });
    await db.deleteProject(req.params.id);
    res.redirect('/projects?message=Project deleted successfully');
  } catch (e) {
    console.error('Delete project error:', e);
    res.redirect('/projects?error=Failed to delete project');
  }
});

// === FEATURE REQUESTS ===

// Feature Request API
router.post('/api/feature-request', apiAuth, async (req, res) => {
  try {
    const { text, page } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Text is required' });
    await db.createFeatureRequest(req.user.id, req.user.name, req.user.email, text.trim(), page || 'unknown');
    // Telegram notification
    const tgToken = process.env.TELEGRAM_BOT_TOKEN;
    const tgChat = process.env.TELEGRAM_CHAT_ID;
    if (tgToken && tgChat) {
      const msg = `\u{1F4A1} Feature Request\nFrom: ${req.user.name} (${req.user.email})\nPage: ${page || 'unknown'}\n\n${text.trim()}`;
      fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: tgChat, text: msg })
      }).catch(err => console.error('Telegram notify failed:', err.message));
    }
    res.json({ success: true });
  } catch (e) {
    console.error('Feature request error:', e);
    res.status(500).json({ error: 'Failed to submit feature request' });
  }
});

// Admin: Feature Requests list
router.get('/admin/feature-requests', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const requests = await db.getAllFeatureRequests();
    res.render('admin/feature-requests', { user: req.user, requests, currentPage: 'admin-feature-requests' });
  } catch (e) {
    console.error('Feature requests page error:', e);
    res.status(500).send('Error loading feature requests');
  }
});

// === FILE MANAGEMENT ===

// Delete file (API - works from portal and session)
router.delete('/api/files/:id', apiAuth, verifyFileOwnership, async (req, res) => {
  try {
    const file = await db.getFile(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    // Log deletion
    await db.logAction(req.user.id, 'file_delete', { filename: file.filename, projectId: file.project_id }, req.ip);

    // Delete from disk
    const fp = path.join(uploadsDir, file.filename || file.original_name);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
    // Delete from DB
    await db.deleteFile(req.params.id);
    res.json({ success: true });
  } catch (e) {
    console.error('Delete file error:', e);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// === ADMIN SESSION MANAGEMENT ===

// List all sessions across all projects
router.get('/admin/sessions', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const sessions = await db.getAllSessions();
  // Parse transcript to get message count
  const enriched = sessions.map(s => {
    let messageCount = 0;
    try { messageCount = JSON.parse(s.transcript || '[]').length; } catch {}
    return { ...s, message_count: messageCount };
  });
  res.render('admin/sessions', {
    user: req.user,
    sessions: enriched,
    title: 'All Sessions',
    currentPage: 'admin-sessions',
    query: req.query
  });
});

// Admin: view/access project session (same UI as customer)
router.get('/admin/projects/:id/session', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');

  // Check for existing active session
  let activeSession = await db.getLatestSessionForProject(req.params.id);
  if (!activeSession || activeSession.status === 'completed') {
    // Create new session
    const result = await db.createSession(req.params.id);
    activeSession = { id: result.lastInsertRowid };
  }

  res.redirect(`/voice-session?project=${encodeProjectId(req.params.id)}&session=${activeSession.id}`);
});

// Admin: create a new session for a project
router.post('/admin/projects/:id/session/create', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');
  const result = await db.createSession(req.params.id);
  res.redirect(`/voice-session?project=${encodeProjectId(req.params.id)}&session=${result.lastInsertRowid}`);
});

// Admin: view session transcript (standalone page)
router.get('/admin/sessions/:id/view', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const session = await db.getSession(req.params.id);
  if (!session) return res.status(404).send('Session not found');
  const project = await db.getProject(session.project_id);
  let transcript = [];
  let requirements = {};
  try { transcript = JSON.parse(session.transcript || '[]'); } catch {}
  try { requirements = JSON.parse(session.requirements || '{}'); } catch {}
  res.render('admin/session-view', {
    user: req.user,
    session,
    project,
    transcript,
    requirements,
    title: `Session #${session.id} - ${project ? project.name : 'Unknown'}`,
    currentPage: 'admin-sessions'
  });
});

module.exports = router;
