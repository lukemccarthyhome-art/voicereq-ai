const router = require('express').Router();
const crypto = require('crypto');
const db = require('../database-adapter');
const auth = require('../auth');
const { encodeProjectId } = require('../helpers/ids');
const { sendInviteEmail, isValidEmail } = require('../helpers/email-sender');

// Helper: check if user can manage shares (owner or admin permission)
const canManageShares = async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) { res.status(404).json({ error: 'Project not found' }); return null; }
  if (req.user.role === 'admin') return project;
  if (project.user_id === req.user.id) return project;
  const share = await db.getShareByProjectAndUser(req.params.id, req.user.id);
  if (share && share.permission === 'admin') return project;
  res.status(403).json({ error: 'Only project owner or admin collaborators can manage sharing' });
  return null;
};

// Share a project (admin route)
router.post('/admin/projects/:id/share', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    const { email, permission } = req.body;
    if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
    if (!['admin', 'user', 'readonly'].includes(permission)) return res.status(400).json({ error: 'Invalid permission' });

    const inviterUser = await db.getUserById(req.user.id);
    if (inviterUser && inviterUser.email === email) return res.status(400).json({ error: 'Cannot share with yourself' });

    const token = crypto.randomBytes(32).toString('hex');
    await db.shareProject(req.params.id, email, permission, req.user.id, token);

    const baseUrl = req.protocol + '://' + req.get('host');
    const signupLink = `${baseUrl}/signup?invite=${token}`;
    const projectLink = `${baseUrl}/projects/${req.params.id}`;
    const emailResult = await sendInviteEmail(email, req.user.name, project.name, permission, signupLink, projectLink);

    res.json({ success: true, emailSent: emailResult.sent, signupLink: emailResult.sent ? null : signupLink });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// List shares (admin)
router.get('/admin/projects/:id/shares', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const shares = await db.getProjectShares(req.params.id);
  res.json({ shares });
});

// Update share permission (admin)
router.put('/admin/projects/:id/share/:shareId', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const { permission } = req.body;
  if (!['admin', 'user', 'readonly'].includes(permission)) return res.status(400).json({ error: 'Invalid permission' });
  await db.updateSharePermission(req.params.shareId, permission);
  res.json({ success: true });
});

// Remove share (admin)
router.delete('/admin/projects/:id/share/:shareId', auth.authenticate, auth.requireAdmin, async (req, res) => {
  await db.removeShare(req.params.shareId);
  res.json({ success: true });
});

// Share a project (customer route - must be owner or admin collaborator)
router.post('/customer/projects/:id/share', auth.authenticate, async (req, res) => {
  try {
    const project = await canManageShares(req, res);
    if (!project) return;
    const { email, permission } = req.body;
    if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
    if (!['admin', 'user', 'readonly'].includes(permission)) return res.status(400).json({ error: 'Invalid permission' });

    const inviterUser = await db.getUserById(req.user.id);
    if (inviterUser && inviterUser.email === email) return res.status(400).json({ error: 'Cannot share with yourself' });

    const token = crypto.randomBytes(32).toString('hex');
    await db.shareProject(req.params.id, email, permission, req.user.id, token);

    const baseUrl = req.protocol + '://' + req.get('host');
    const signupLink = `${baseUrl}/signup?invite=${token}`;
    const projectLink = `${baseUrl}/projects/${req.params.id}`;
    const emailResult = await sendInviteEmail(email, req.user.name, project.name, permission, signupLink, projectLink);

    res.json({ success: true, emailSent: emailResult.sent, signupLink: emailResult.sent ? null : signupLink });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// List shares (customer)
router.get('/customer/projects/:id/shares', auth.authenticate, async (req, res) => {
  const project = await canManageShares(req, res);
  if (!project) return;
  const shares = await db.getProjectShares(req.params.id);
  res.json({ shares });
});

// Update share permission (customer)
router.put('/customer/projects/:id/share/:shareId', auth.authenticate, async (req, res) => {
  const project = await canManageShares(req, res);
  if (!project) return;
  const { permission } = req.body;
  if (!['admin', 'user', 'readonly'].includes(permission)) return res.status(400).json({ error: 'Invalid permission' });
  await db.updateSharePermission(req.params.shareId, permission);
  res.json({ success: true });
});

// Remove share (customer)
router.delete('/customer/projects/:id/share/:shareId', auth.authenticate, async (req, res) => {
  const project = await canManageShares(req, res);
  if (!project) return;
  await db.removeShare(req.params.shareId);
  res.json({ success: true });
});

module.exports = router;
