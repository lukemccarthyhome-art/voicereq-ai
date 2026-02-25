const db = require('../database-adapter');
const auth = require('../auth');
const { resolveProjectId } = require('../helpers/ids');

// API auth middleware (checks cookie token for API routes)
const apiAuth = async (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = require('jsonwebtoken').verify(token, auth.JWT_SECRET);
    req.user = await db.getUserById(decoded.id);
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
};

// Optional auth — sets req.user if valid cookie, but doesn't block unauthenticated requests
const optionalAuth = async (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return next();
  try {
    const decoded = require('jsonwebtoken').verify(token, auth.JWT_SECRET);
    req.user = await db.getUserById(decoded.id);
  } catch {}
  next();
};

// Ownership check: verify session belongs to the requesting user (admins bypass)
const verifySessionOwnership = async (req, res, next) => {
  if (req.user.role === 'admin') return next();
  const sessionId = req.params.id;
  const session = await db.getSession(sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  const project = await db.getProject(session.project_id);
  if (!project || project.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  req.sessionData = session;
  next();
};

const verifyProjectOwnership = async (req, res, next) => {
  if (req.user.role === 'admin') return next();
  const projectId = resolveProjectId(req.body.projectId || req.body.project_id || req.params.projectId);
  if (!projectId) return res.status(400).json({ error: 'Project ID required' });
  const project = await db.getProject(projectId);
  if (!project || project.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  next();
};

// Permission hierarchy: admin > user > readonly
const PERMISSION_LEVELS = { readonly: 1, user: 2, admin: 3 };

const verifyProjectAccess = (requiredPermission = 'readonly') => {
  return async (req, res, next) => {
    const projectId = resolveProjectId(req.params.id || req.params.projectId || req.body.projectId || req.body.project_id);
    if (!projectId) return res.status(400).json({ error: 'Project ID required' });
    // Admin role always allowed
    if (req.user.role === 'admin') { req.projectAccess = 'owner'; return next(); }
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    // Owner always allowed
    if (project.user_id === req.user.id) { req.projectAccess = 'owner'; return next(); }
    // Check share
    const share = await db.getShareByProjectAndUser(projectId, req.user.id);
    if (share && PERMISSION_LEVELS[share.permission] >= PERMISSION_LEVELS[requiredPermission]) {
      req.projectAccess = share.permission;
      req.projectShare = share;
      return next();
    }
    return res.status(403).render ? res.status(403).send('Forbidden — you do not have access to this project') : res.status(403).json({ error: 'Forbidden' });
  };
};

const verifyFileOwnership = async (req, res, next) => {
  if (req.user.role === 'admin') return next();
  const fileId = req.params.id;
  const file = await db.getFileById(fileId);
  if (!file) return res.status(404).json({ error: 'File not found' });
  const project = await db.getProject(file.project_id);
  if (!project || project.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  next();
};

module.exports = {
  apiAuth,
  optionalAuth,
  verifySessionOwnership,
  verifyProjectOwnership,
  verifyProjectAccess,
  verifyFileOwnership,
  PERMISSION_LEVELS
};
