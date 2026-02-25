const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const db = require('../database-adapter');
const auth = require('../auth');
const { DESIGNS_DIR, PROPOSALS_DIR, uploadsDir } = require('../helpers/paths');
const { encodeProjectId, resolveProjectId } = require('../helpers/ids');
const { PERMISSION_LEVELS } = require('../middleware/auth-middleware');
const { loadNewestDesign } = require('./design');
const { loadNewestProposal, getEngineBuildId } = require('./proposals');

// Decode hashed IDs in :id route params
router.param('id', (req, res, next, val) => {
  req.params.id = resolveProjectId(val);
  next();
});

// Customer: archive project
router.post('/customer/projects/:id/archive', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project || project.user_id !== req.user.id) return res.status(403).send('Forbidden');
    await db.updateProject(req.params.id, project.name, project.description, 'archived');
    res.redirect('/projects?message=Project+archived');
  } catch (e) {
    res.redirect(`/projects/${encodeProjectId(req.params.id)}?error=Archive+failed`);
  }
});

router.post('/customer/projects/:id/unarchive', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project || project.user_id !== req.user.id) return res.status(403).send('Forbidden');
    await db.updateProject(req.params.id, project.name, project.description, 'active');
    res.redirect('/projects/archived?message=Project+unarchived');
  } catch (e) {
    res.redirect('/projects/archived?error=Unarchive+failed');
  }
});

// Customer: archived projects
router.get('/projects/archived', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const projects = await db.getArchivedProjectsByUser(req.user.id);
  res.render('customer/projects-archived', { user: req.user, projects, title: 'Archived Projects', currentPage: 'customer-projects' });
});

// Customer: requirements page
router.get('/customer/projects/:id/requirements', auth.authenticate, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    if (req.user.role === 'customer' && project.user_id !== req.user.id) {
      const share = await db.getShareByProjectAndUser(req.params.id, req.user.id);
      if (!share) return res.status(403).send('Forbidden');
    }
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
    res.render('customer/project-requirements', { user: req.user, project, requirements: allRequirements, title: project.name + ' - Requirements', currentPage: 'customer-projects' });
  } catch (e) {
    console.error('Requirements error:', e);
    res.status(500).send('Failed to load requirements');
  }
});

// Customer: answer assigned question
router.post('/customer/projects/:id/design/answer', auth.authenticate, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (req.user.role === 'customer' && project.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

    const { designId, question, answer } = req.body;
    const filePath = path.join(DESIGNS_DIR, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Design not found' });
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    design.customerAnswers = design.customerAnswers || [];
    design.customerAnswers.push({ question, answer, from: req.user.email, ts: new Date().toISOString() });
    fs.writeFileSync(filePath, JSON.stringify(design, null, 2));

    res.redirect(`/projects/${encodeProjectId(projectId)}`);
  } catch (e) {
    console.error('Customer answer error:', e);
    res.status(500).send('Failed to save answer');
  }
});

// === CUSTOMER ROUTES ===

router.get('/dashboard', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const projects = await db.getProjectsByUser(req.user.id);
  const fullUser = await db.getUserById(req.user.id);
  const sharedProjects = (fullUser && typeof db.getSharedProjects === 'function') ? await db.getSharedProjects(req.user.id, fullUser.email) : [];

  // Enrich projects with stage info
  const enriched = projects.map(p => {
    const designFiles = fs.existsSync(DESIGNS_DIR) ? fs.readdirSync(DESIGNS_DIR).filter(f => f.startsWith(`design-${p.id}-`)).sort().reverse() : [];
    const proposalFiles = fs.existsSync(PROPOSALS_DIR) ? fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${p.id}-`)).sort().reverse() : [];
    let hasDesign = false, hasProposal = false, isApproved = false, questionCount = 0;
    if (designFiles.length > 0) {
      try { const d = JSON.parse(fs.readFileSync(path.join(DESIGNS_DIR, designFiles[0]), 'utf8')); hasDesign = !!d.published; if (d.questions) questionCount = d.questions.filter(q => !q.answered).length; } catch {}
    }
    if (proposalFiles.length > 0) {
      try { const pr = JSON.parse(fs.readFileSync(path.join(PROPOSALS_DIR, proposalFiles[0]), 'utf8')); hasProposal = !!pr.published; isApproved = !!pr.approvedAt; } catch {}
    }
    const isSubmitted = p.status === 'completed' && !hasDesign;
    const stage = isApproved ? 'approved' : hasProposal ? 'proposal' : hasDesign ? 'design' : isSubmitted ? 'submitted' : (p.session_count > 0 ? 'session' : 'new');
    return { ...p, stage, hasDesign, hasProposal, isApproved, isSubmitted, questionCount };
  });

  // Fetch billing status for warning banners
  let billingWarnings = [];
  try {
    const subs = await db.getSubscriptionsByUser(req.user.id);
    if (subs.some(s => s.status === 'past_due')) billingWarnings.push('past_due');
    if (subs.some(s => s.status === 'paused')) billingWarnings.push('paused');
  } catch (e) { /* billing tables may not exist yet */ }

  res.render('customer/dashboard', {
    user: req.user,
    projects: enriched,
    sharedProjects,
    billingWarnings,
    isNewProject: req.query.new === 'true',
    title: 'Dashboard',
    currentPage: 'customer-dashboard',
    breadcrumbs: [{ name: 'Dashboard' }]
  });
});

// Redirect /projects to /dashboard (merged pages)
router.get('/projects', auth.authenticate, auth.requireCustomer, (req, res) => {
  const query = req.query.new === 'true' ? '?new=true' : '';
  res.redirect('/dashboard' + query);
});

router.get('/projects/new', auth.authenticate, auth.requireCustomer, (req, res) => {
  res.redirect('/dashboard?new=true');
});

router.post('/projects', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const { name, description } = req.body;
    const result = await db.createProject(req.user.id, name, description);
    await db.logAction(req.user.id, 'project_create', { name, projectId: result.lastInsertRowid }, req.ip);
    res.redirect(`/projects/${result.lastInsertRowid}?message=Project created successfully`);
  } catch (e) {
    console.error('Create project error:', e);
    res.redirect('/projects?error=Failed to create project');
  }
});

router.get('/projects/:id', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');
  // Check ownership or share access
  let projectAccess = 'owner';
  let isShared = false;
  if (project.user_id !== req.user.id) {
    const share = await db.getShareByProjectAndUser(req.params.id, req.user.id);
    if (!share) return res.status(404).send('Project not found');
    projectAccess = share.permission;
    isShared = true;
  }

  const sessions = await db.getSessionsByProject(req.params.id);
  const files = await db.getFilesByProject(req.params.id);
  const activeSession = await db.getLatestSessionForProject(req.params.id);

  // Check for published design and customer questions
  let hasPublishedDesign = false;
  let designApproved = false;
  let customerQuestions = [];
  let customerDesignId = '';
  let customerAnswers = [];
  let hasPublishedProposal = false;
  let proposalApproved = false;
  let hasRequirements = false;
  try {
    const designResult = loadNewestDesign(req.params.id);
    if (designResult && designResult.design) {
      if (designResult.design.published) hasPublishedDesign = true;
      if (designResult.design.approvedAt) designApproved = true;
      customerDesignId = designResult.design.id || '';
      customerAnswers = designResult.design.customerAnswers || [];
      if (designResult.design.questions && Array.isArray(designResult.design.questions)) {
        customerQuestions = designResult.design.questions.filter(q => q.assignedTo === 'customer');
      }
    }
  } catch(e) {}
  // Check if sessions have requirements
  try {
    sessions.forEach(s => {
      const reqs = JSON.parse(s.requirements || '{}');
      if (Object.values(reqs).some(arr => Array.isArray(arr) && arr.length > 0)) hasRequirements = true;
    });
  } catch(e) {}
  try {
    const proposal = loadNewestProposal(req.params.id);
    if (proposal && proposal.published) { hasPublishedProposal = true; proposalApproved = !!proposal.approvedAt; }
  } catch(e) {}

  // Check if current user can manage shares
  const canShare = projectAccess === 'owner' || projectAccess === 'admin';

  // Check if project has been sent to engine
  const engineBuildId = getEngineBuildId(project.id);

  res.render('customer/project', {
    user: req.user,
    project,
    sessions,
    files,
    activeSession,
    hasPublishedDesign,
    designApproved,
    hasPublishedProposal,
    proposalApproved,
    hasRequirements,
    customerQuestions,
    customerDesignId,
    customerAnswers,
    projectAccess,
    isShared,
    canShare,
    engineBuildId,
    title: project.name,
    currentPage: 'customer-projects',
    breadcrumbs: [
      { name: 'Dashboard', url: '/dashboard' },
      { name: 'Projects', url: '/projects' },
      { name: project.name }
    ]
  });
});

router.get('/projects/:id/session', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const project = await db.getProject(req.params.id);
  // Allow session access for owner or shared users with 'user' or 'admin' permission
  let hasAccess = project && project.user_id === req.user.id;
  if (project && !hasAccess) {
    const share = await db.getShareByProjectAndUser(req.params.id, req.user.id);
    hasAccess = share && PERMISSION_LEVELS[share.permission] >= PERMISSION_LEVELS['user'];
  }
  if (!hasAccess) {
    return res.status(404).send('Project not found');
  }

  // Check for existing active session
  let activeSession = await db.getLatestSessionForProject(req.params.id);
  if (!activeSession || activeSession.status === 'completed') {
    const result = await db.createSession(req.params.id);
    activeSession = { id: result.lastInsertRowid };
  }

  res.redirect(`/voice-session?project=${encodeProjectId(req.params.id)}&session=${activeSession.id}`);
});

router.get('/voice-session', auth.authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'voice-session.html'));
});

module.exports = router;
