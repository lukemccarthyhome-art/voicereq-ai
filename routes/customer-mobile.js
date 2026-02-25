const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const db = require('../database-adapter');
const auth = require('../auth');
const { DESIGNS_DIR, PROPOSALS_DIR } = require('../helpers/paths');
const { encodeProjectId } = require('../helpers/ids');
const { PERMISSION_LEVELS } = require('../middleware/auth-middleware');

// Helper to load newest design for a project (imported from design module)
const { loadNewestDesign } = require('./design');
const { loadNewestProposal } = require('./proposals');

// === MOBILE CUSTOMER ROUTES ===

router.get('/m', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const projects = await db.getProjectsByUser(req.user.id);
  const enriched = projects.map(p => {
    const designFiles = fs.existsSync(DESIGNS_DIR) ? fs.readdirSync(DESIGNS_DIR).filter(f => f.startsWith(`design-${p.id}-`)).sort().reverse() : [];
    const proposalFiles = fs.existsSync(PROPOSALS_DIR) ? fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${p.id}-`)).sort().reverse() : [];
    let hasDesign = false, hasProposal = false, isApproved = false;
    if (designFiles.length > 0) { try { const d = JSON.parse(fs.readFileSync(path.join(DESIGNS_DIR, designFiles[0]), 'utf8')); hasDesign = !!d.published; } catch {} }
    if (proposalFiles.length > 0) { try { const pr = JSON.parse(fs.readFileSync(path.join(PROPOSALS_DIR, proposalFiles[0]), 'utf8')); hasProposal = !!pr.published; isApproved = !!pr.approvedAt; } catch {} }
    const stage = isApproved ? 'approved' : hasProposal ? 'proposal' : hasDesign ? 'design' : (p.session_count > 0 ? 'session' : 'new');
    return { ...p, stage };
  });
  res.render('customer/mobile/dashboard', { user: req.user, projects: enriched });
});

router.get('/m/projects', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const projects = await db.getProjectsByUser(req.user.id);
  const enriched = projects.map(p => {
    const designFiles = fs.existsSync(DESIGNS_DIR) ? fs.readdirSync(DESIGNS_DIR).filter(f => f.startsWith(`design-${p.id}-`)).sort().reverse() : [];
    const proposalFiles = fs.existsSync(PROPOSALS_DIR) ? fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${p.id}-`)).sort().reverse() : [];
    let hasDesign = false, hasProposal = false, isApproved = false;
    if (designFiles.length > 0) { try { const d = JSON.parse(fs.readFileSync(path.join(DESIGNS_DIR, designFiles[0]), 'utf8')); hasDesign = !!d.published; } catch {} }
    if (proposalFiles.length > 0) { try { const pr = JSON.parse(fs.readFileSync(path.join(PROPOSALS_DIR, proposalFiles[0]), 'utf8')); hasProposal = !!pr.published; isApproved = !!pr.approvedAt; } catch {} }
    const stage = isApproved ? 'approved' : hasProposal ? 'proposal' : hasDesign ? 'design' : (p.session_count > 0 ? 'session' : 'new');
    return { ...p, stage };
  });
  res.render('customer/mobile/projects', { user: req.user, projects: enriched });
});

router.get('/m/projects/:id', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project || project.user_id !== req.user.id) {
    const share = project ? await db.getShareByProjectAndUser(req.params.id, req.user.id) : null;
    if (!share) return res.status(404).send('Project not found');
  }
  const sessions = await db.getSessionsByProject(req.params.id);
  const files = await db.getFilesByProject(req.params.id);
  let hasPublishedDesign = false, designApproved = false, hasPublishedProposal = false, proposalApproved = false, hasRequirements = false, customerQuestions = [];
  try {
    const designResult = loadNewestDesign(req.params.id);
    if (designResult && designResult.design) {
      if (designResult.design.published) hasPublishedDesign = true;
      if (designResult.design.approvedAt) designApproved = true;
      if (designResult.design.questions && Array.isArray(designResult.design.questions)) {
        customerQuestions = designResult.design.questions.filter(q => q.assignedTo === 'customer');
      }
    }
  } catch(e) {}
  try { sessions.forEach(s => { const reqs = JSON.parse(s.requirements || '{}'); if (Object.values(reqs).some(arr => Array.isArray(arr) && arr.length > 0)) hasRequirements = true; }); } catch(e) {}
  try { const proposal = loadNewestProposal(req.params.id); if (proposal && proposal.published) { hasPublishedProposal = true; proposalApproved = !!proposal.approvedAt; } } catch(e) {}
  res.render('customer/mobile/project', { user: req.user, project, sessions, files, hasPublishedDesign, designApproved, hasPublishedProposal, proposalApproved, hasRequirements, customerQuestions });
});

router.get('/m/projects/:id/design', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    if (project.user_id !== req.user.id) {
      const share = await db.getShareByProjectAndUser(req.params.id, req.user.id);
      if (!share) return res.status(403).send('Forbidden');
    }
    const result = loadNewestDesign(req.params.id);
    if (!result || !result.design.published) return res.status(404).send('No published design available');
    const { design } = result;
    res.render('customer/mobile/design', { user: req.user, project, design });
  } catch (e) {
    console.error('Mobile design view error:', e);
    res.status(500).send('Failed to load design');
  }
});

router.get('/m/projects/:id/proposal', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    if (project.user_id !== req.user.id) {
      const share = await db.getShareByProjectAndUser(req.params.id, req.user.id);
      if (!share) return res.status(403).send('Forbidden');
    }
    const proposal = loadNewestProposal(req.params.id);
    if (!proposal || !proposal.published) return res.status(404).send('No published proposal');
    res.render('customer/mobile/proposal', { user: req.user, project, proposal });
  } catch (e) {
    console.error('Mobile proposal view error:', e);
    res.status(500).send('Failed to load proposal');
  }
});

router.get('/m/projects/:id/voice', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');
  let hasAccess = project.user_id === req.user.id;
  if (!hasAccess) {
    const share = await db.getShareByProjectAndUser(req.params.id, req.user.id);
    hasAccess = share && PERMISSION_LEVELS[share.permission] >= PERMISSION_LEVELS['user'];
  }
  if (!hasAccess) return res.status(404).send('Project not found');
  let activeSession = await db.getLatestSessionForProject(req.params.id);
  if (!activeSession || activeSession.status === 'completed') {
    const result = await db.createSession(req.params.id);
    activeSession = { id: result.lastInsertRowid };
  }
  res.render('customer/mobile/voice', { user: req.user, project, sessionId: activeSession.id });
});

router.get('/m/profile', auth.authenticate, auth.requireCustomer, async (req, res) => {
  res.render('customer/mobile/profile', { user: req.user });
});

module.exports = router;
