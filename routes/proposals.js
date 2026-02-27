const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const db = require('../database-adapter');
const auth = require('../auth');
const emails = require('../emails');
const { PROPOSALS_DIR, uploadsDir } = require('../helpers/paths');
const { encodeProjectId, resolveProjectId } = require('../helpers/ids');
const { sendMortiEmail } = require('../helpers/email-sender');
const generationStatus = require('../helpers/generation-status');
const { loadNewestDesign, saveDesign } = require('./design');

// Decode hashed IDs in :id route params
router.param('id', (req, res, next, val) => {
  req.params.id = resolveProjectId(val);
  next();
});

// Helper: load newest proposal for a project
const loadNewestProposal = (projectId) => {
  const files = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${projectId}-`)).sort().reverse();
  if (files.length === 0) return null;
  return JSON.parse(fs.readFileSync(path.join(PROPOSALS_DIR, files[0]), 'utf8'));
};

// Helper to get engine build ID from project's design
function getEngineBuildId(projectId) {
  const result = loadNewestDesign(projectId);
  if (!result || !result.design) return null;
  return result.design.engineBuildId || null;
}

// Poll generation status
router.get('/admin/projects/:id/generation-status', auth.authenticate, auth.requireAdmin, (req, res) => {
  const status = generationStatus[req.params.id];
  if (!status) return res.json({ status: 'idle' });
  res.json(status);
});

// View proposal
router.get('/admin/projects/:id/proposal', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');

  const proposal = loadNewestProposal(req.params.id);
  const designResult = loadNewestDesign(req.params.id);
  const genStatus = generationStatus[req.params.id];

  res.render('admin/project-proposal', {
    user: req.user,
    project,
    proposal,
    design: designResult ? designResult.design : null,
    query: req.query,
    generating: genStatus && genStatus.type === 'proposal' && genStatus.status === 'generating',
    title: project.name + ' - Proposal',
    currentPage: 'admin-projects'
  });
});

// Generate proposal
router.post('/admin/projects/:id/generate-proposal', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const projectId = req.params.id;

  // Quick validation, then redirect immediately
  try {
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).send('Project not found');

    const designResult = loadNewestDesign(projectId);
    if (!designResult || !designResult.design) {
      return res.redirect(`/admin/projects/${encodeProjectId(projectId)}/proposal?error=No design found. Extract a design first.`);
    }

    // Mark as generating and redirect immediately
    generationStatus[projectId] = { type: 'proposal', status: 'generating', startedAt: Date.now() };
    res.redirect(`/admin/projects/${encodeProjectId(projectId)}/proposal`);

    // Generate in background
    const design = designResult.design;
    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    const discount = {
      upfront: req.body.discountUpfront ? parseFloat(req.body.discountUpfront) : null,
      annual: req.body.discountAnnual ? parseFloat(req.body.discountAnnual) : null
    };
    const hasDiscount = discount.upfront || discount.annual;
    generateProposalAsync(projectId, project, design, OPENAI_KEY, req.user, discount).catch(err => {
      console.error('Background proposal generation failed:', err);
      generationStatus[projectId] = { type: 'proposal', status: 'error', error: err.message };
    });
  } catch(e) {
    console.error('Proposal generation error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(projectId)}/proposal?error=${encodeURIComponent(e.message)}`);
  }
});

// Proposal chat - save feedback
router.post('/admin/projects/:id/proposal/chat', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Empty message' });

    // Find newest proposal
    const files = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${projectId}-`)).sort().reverse();
    if (files.length === 0) return res.status(404).json({ error: 'No proposal found' });

    const filePath = path.join(PROPOSALS_DIR, files[0]);
    const proposal = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    proposal.chat = proposal.chat || [];
    const userMsg = { from: req.user.email, text: text.trim(), ts: new Date().toISOString() };
    proposal.chat.push(userMsg);

    fs.writeFileSync(filePath, JSON.stringify(proposal, null, 2));
    res.json({ ok: true, messages: [userMsg] });
  } catch(e) {
    console.error('Proposal chat error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Publish proposal
router.post('/admin/projects/:id/proposal/publish', auth.authenticate, auth.requireAdmin, (req, res) => {
  const files = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${req.params.id}-`)).sort().reverse();
  if (files.length === 0) return res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/proposal?error=No proposal found`);
  const filePath = path.join(PROPOSALS_DIR, files[0]);
  const proposal = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  proposal.published = true;
  proposal.publishedAt = new Date().toISOString();
  fs.writeFileSync(filePath, JSON.stringify(proposal, null, 2));

  // Send proposal-ready email to project owner
  (async () => {
    try {
      const project = await db.getProject(req.params.id);
      if (project) {
        const owner = await db.getUserById(project.user_id);
        if (owner && owner.email) {
          const mail = emails.proposalReadyEmail(project.name, req.params.id);
          await sendMortiEmail(owner.email, mail.subject, mail.html);
        }
      }
    } catch (e) { console.error('[Email] Proposal ready notification failed:', e.message); }
  })();

  res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/proposal`);
});

// Unpublish proposal
router.post('/admin/projects/:id/proposal/unpublish', auth.authenticate, auth.requireAdmin, (req, res) => {
  const files = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${req.params.id}-`)).sort().reverse();
  if (files.length === 0) return res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/proposal?error=No proposal found`);
  const filePath = path.join(PROPOSALS_DIR, files[0]);
  const proposal = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  proposal.published = false;
  delete proposal.publishedAt;
  delete proposal.approvedAt;
  delete proposal.approvedBy;
  fs.writeFileSync(filePath, JSON.stringify(proposal, null, 2));
  res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/proposal`);
});

// Delete all proposals for a project
router.post('/admin/projects/:id/proposal/delete', auth.authenticate, auth.requireAdmin, (req, res) => {
  const files = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${req.params.id}-`));
  files.forEach(f => fs.unlinkSync(path.join(PROPOSALS_DIR, f)));
  res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/proposal`);
});

// Customer: view published proposal
router.get('/customer/projects/:id/proposal', auth.authenticate, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');
  if (req.user.role === 'customer' && project.user_id !== req.user.id) {
    const share = await db.getShareByProjectAndUser(req.params.id, req.user.id);
    if (!share) return res.status(403).send('Forbidden');
  }
  const proposal = loadNewestProposal(req.params.id);
  if (!proposal || !proposal.published) return res.status(404).send('No published proposal');
  res.render('customer/project-proposal', { user: req.user, project, proposal, title: project.name + ' - Proposal', currentPage: 'customer-projects' });
});

// Customer: approve proposal
router.post('/customer/projects/:id/proposal/approve', auth.authenticate, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');
  if (req.user.role === 'customer' && project.user_id !== req.user.id) return res.status(403).send('Forbidden');
  const files = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${req.params.id}-`)).sort().reverse();
  if (files.length === 0) return res.status(404).send('No proposal');
  const filePath = path.join(PROPOSALS_DIR, files[0]);
  const proposal = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!proposal.published) return res.status(403).send('Proposal not published');
  proposal.approvedAt = new Date().toISOString();
  proposal.approvedBy = req.user.email;
  proposal.status = 'approved';
  fs.writeFileSync(filePath, JSON.stringify(proposal, null, 2));
  res.redirect(`/customer/projects/${encodeProjectId(req.params.id)}/proposal`);
});

// --- Customer Onboarding (proxied to Morti Engine) ---

// Customer onboarding page
router.get('/customer/projects/:id/onboarding', auth.authenticate, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).render('error', { message: 'Project not found' });

    const buildId = getEngineBuildId(req.params.id);
    if (!buildId) return res.render('customer/project-onboarding', { user: req.user, project, spec: null, state: null, buildId: null, error: 'No build has been created for this project yet.', title: project.name + ' - Onboarding' });

    const engineUrl = process.env.ENGINE_API_URL;
    const engineSecret = process.env.ENGINE_API_SECRET;
    if (!engineUrl || !engineSecret) return res.render('customer/project-onboarding', { user: req.user, project, spec: null, state: null, buildId, error: 'Build engine not configured.', title: project.name + ' - Onboarding' });

    const response = await fetch(`${engineUrl}/api/builds/${buildId}/onboarding`, {
      headers: { 'Authorization': `Bearer ${engineSecret}` },
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error(`Engine returned ${response.status}`);
    const data = await response.json();

    res.render('customer/project-onboarding', {
      user: req.user, project, spec: data.spec, state: data.state, buildId,
      error: null, title: project.name + ' - Onboarding'
    });
  } catch (e) {
    console.error('Customer onboarding error:', e);
    res.render('customer/project-onboarding', { user: req.user, project: { name: 'Error' }, spec: null, state: null, buildId: null, error: 'Failed to load onboarding: ' + e.message, title: 'Onboarding Error' });
  }
});

// Customer save onboarding data
router.post('/customer/projects/:id/onboarding', auth.authenticate, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const buildId = getEngineBuildId(req.params.id);
    if (!buildId) return res.status(400).json({ error: 'No build found' });

    const engineUrl = process.env.ENGINE_API_URL;
    const engineSecret = process.env.ENGINE_API_SECRET;

    const response = await fetch(`${engineUrl}/api/builds/${buildId}/onboarding/external`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(10000)
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    console.error('Customer onboarding save error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Customer: approve design
router.post('/customer/projects/:id/design/approve', auth.authenticate, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    if (req.user.role === 'customer' && project.user_id !== req.user.id) return res.status(403).send('Forbidden');
    const result = loadNewestDesign(req.params.id);
    if (!result || !result.design.published) return res.status(404).send('No published design');
    result.design.approvedAt = new Date().toISOString();
    result.design.approvedBy = req.user.email;
    saveDesign(result.design);
    res.redirect(`/customer/projects/${encodeProjectId(req.params.id)}/design`);
  } catch (e) {
    console.error('Design approve error:', e);
    res.redirect(`/customer/projects/${encodeProjectId(req.params.id)}/design?error=Approve+failed`);
  }
});

// --- Send to Morti Engine ---
// NOTE: In production, ENGINE_API_URL should use HTTPS
router.post('/admin/projects/:id/send-to-engine', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const result = loadNewestDesign(projectId);
    if (!result || !result.design) return res.status(400).json({ error: 'No design found for this project' });

    const engineUrl = process.env.ENGINE_API_URL;
    const engineSecret = process.env.ENGINE_API_SECRET;
    if (!engineUrl || !engineSecret) return res.status(500).json({ error: 'Engine API not configured (ENGINE_API_URL / ENGINE_API_SECRET)' });

    // --- Gather full project data ---
    const design = result.design;
    const designPayload = design.sections || {};
    if (design.summary) designPayload.summary = design.summary;
    if (design.designMarkdown) designPayload.designMarkdown = design.designMarkdown;
    if (design.customerDesign) designPayload.customerDesign = design.customerDesign;
    if (design.engineDesign) designPayload.engineDesign = design.engineDesign;

    // Requirements from project record
    let requirements = {};
    try { requirements = JSON.parse(project.requirements || '{}'); } catch (e) { /* empty */ }

    // Session transcript
    const sessions = await db.getSessionsByProject(projectId);
    let transcript = [];
    for (const sess of sessions) {
      try {
        const fullSession = await db.getSession(sess.id);
        if (fullSession && fullSession.transcript) {
          const msgs = JSON.parse(fullSession.transcript || '[]');
          transcript = transcript.concat(msgs);
        }
      } catch (e) { /* skip */ }
    }

    // Files — include metadata + base64 content for text-based files, metadata-only for large binaries
    const dbFiles = await db.getFilesByProject(projectId);
    const files = [];
    for (const f of dbFiles) {
      const fileEntry = {
        name: f.original_name || f.filename,
        type: f.mime_type || f.type || 'unknown',
        description: f.ai_description || f.description || '',
        size: f.size || 0
      };
      // Include file content for text/small files (< 2MB)
      try {
        const filePath = path.join(uploadsDir, f.filename || f.original_name);
        if (fs.existsSync(filePath)) {
          const stats = fs.statSync(filePath);
          if (stats.size < 2 * 1024 * 1024) {
            const content = fs.readFileSync(filePath);
            fileEntry.contentBase64 = content.toString('base64');
            fileEntry.actualSize = stats.size;
          } else {
            fileEntry.contentBase64 = null;
            fileEntry.note = 'File too large to transfer inline (> 2MB)';
          }
        }
      } catch (e) { /* file not on disk, metadata only */ }
      files.push(fileEntry);
    }

    const payload = {
      design: designPayload,
      requirements: requirements,
      transcript: transcript,
      files: files,
      projectName: project.name,
      projectDescription: project.description || '',
      projectId: projectId,
      designId: design.id
    };

    const response = await fetch(`${engineUrl}/api/planner/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${engineSecret}`
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(60000)
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      return res.status(response.status).json({ error: errData.error || `Engine returned ${response.status}` });
    }

    const engineResult = await response.json();
    const planId = engineResult.planId || projectId;

    // Poll Engine until build is done (max 120s)
    let buildId = engineResult.buildId || null;
    if (!buildId && planId) {
      const pollStart = Date.now();
      const maxWait = 120000;
      while (Date.now() - pollStart < maxWait) {
        await new Promise(r => setTimeout(r, 3000));
        try {
          const statusRes = await fetch(`${engineUrl}/api/planner/status/${planId}`, {
            headers: { 'Authorization': `Bearer ${engineSecret}` },
            signal: AbortSignal.timeout(10000)
          });
          if (statusRes.ok) {
            const statusData = await statusRes.json();
            if (statusData.status === 'done') { buildId = statusData.buildId; break; }
            if (statusData.status === 'error') throw new Error(statusData.error || 'Engine build failed');
          }
        } catch (pollErr) {
          if (pollErr.message.includes('Engine build failed')) throw pollErr;
          // transient error, keep polling
        }
      }
      if (!buildId) throw new Error('Engine build timed out after 120s');
    }

    // Track sent status on the design
    design.sentToEngineAt = new Date().toISOString();
    design.enginePlanId = planId;
    design.engineBuildId = buildId;
    saveDesign(design);

    res.json({
      success: true,
      planId: engineResult.planId,
      sentAt: design.sentToEngineAt
    });
  } catch (e) {
    console.error('Send to engine error:', e);
    res.status(500).json({ error: 'Failed to send to engine: ' + e.message });
  }
});

// --- Background proposal generation ---
async function generateProposalAsync(projectId, project, design, OPENAI_KEY, user, discount) {
  try {

    // Build context (support both old and new format)
    const sections = design.sections || {};
    const cd = design.customerDesign || {};
    const ed = design.engineDesign || {};
    const costBenefit = sections.CostBenefitAnalysis || cd.TimelineAndInvestment || 'Not yet established';
    const buildEffort = sections.BuildEffortEstimate || cd.TimelineAndInvestment || 'Not specified';
    const executiveSummary = cd.ExecutiveSummary || sections.ExecutiveSummary || design.summary || '';
    const coreWorkflow = cd.HowItWorks || sections.CoreWorkflow || '';
    const architecture = ed.TechnicalArchitecture || sections.SimplifiedArchitecture || '';
    const assumptions = sections.Assumptions || '';
    const phase2 = sections.Phase2Enhancements || '';
    const risks = ed.RiskRegister || sections.RisksAndMitigations || '';

    // Include customer answers and admin notes
    let extraContext = '';
    if (design.customerAnswers && design.customerAnswers.length > 0) {
      extraContext += '\n\nCUSTOMER ANSWERS:\n' + design.customerAnswers.map(a => `Q: ${a.question}\nA: ${a.answer}`).join('\n\n');
    }
    if (design.answers && design.answers.length > 0) {
      extraContext += '\n\nADMIN ANSWERS:\n' + design.answers.map(a => `Q: ${a.question}\nA: ${a.answer}`).join('\n\n');
    }

    // Include full previous proposal for carry-forward
    const prevProposal = loadNewestProposal(projectId);
    if (prevProposal) {
      // Strip metadata, keep content
      const prevContent = { ...prevProposal };
      delete prevContent.id; delete prevContent.projectId; delete prevContent.createdAt;
      delete prevContent.designId; delete prevContent.status; delete prevContent.chat;
      delete prevContent.published; delete prevContent.publishedAt;
      delete prevContent.approvedAt; delete prevContent.approvedBy;
      extraContext += '\n\nEXISTING PROPOSAL (carry forward — preserve ALL content unless specifically asked to change):\n';
      extraContext += JSON.stringify(prevContent, null, 2);

      if (prevProposal.chat && prevProposal.chat.length > 0) {
        extraContext += '\n\nADMIN FEEDBACK (CRITICAL — address every point, adjust the existing proposal accordingly):\n';
        extraContext += prevProposal.chat.map(m => `${m.from}: ${m.text}`).join('\n');
      }
    }

    // Handle discount
    if (discount && (discount.upfront || discount.annual)) {
      let discountInstructions = '\n\nDISCOUNT INSTRUCTIONS:\n';
      if (discount.upfront && discount.upfront > 0 && discount.upfront <= 100) {
        discountInstructions += `- Apply ${discount.upfront}% discount to the UPFRONT fee. Include "originalTotal" field in upfrontFee showing pre-discount amount, and set "total" to the discounted amount.\n`;
      }
      if (discount.annual && discount.annual > 0 && discount.annual <= 100) {
        discountInstructions += `- Apply ${discount.annual}% discount to the ANNUAL fee. Include "originalTotal" field in annualFee showing pre-discount amount, and set "total" to the discounted amount. Recalculate monthlyEquivalent.\n`;
      }
      discountInstructions += `Add a "discount" field to root JSON: { "upfront": ${discount.upfront || 0}, "annual": ${discount.annual || 0}, "reason": "Negotiated discount" }. Recalculate ROI based on discounted prices.`;
      extraContext += discountInstructions;
    }

    const model = process.env.LLM_MODEL || process.env.OPENAI_MODEL || 'gpt-4.1-mini';

    const prompt = `You are a commercially minded product strategist and pricing advisor for Morti Pty Ltd, an AI consultancy based in Melbourne, Australia. You are given a project design. Your task is to produce a clear, honest pricing proposal with exactly TWO fees the client will sign off on.

THE TWO FEES:
1. **Upfront Fee** — covers discovery, design, and implementation to deliver the working system. Based on realistic engineering effort at $400/hour for AI engineering. Be honest about hours required. Include discovery/design AND build in this single upfront number.
2. **Annual Fee** — ongoing support, optimisation, monitoring, and maintenance. This should be 50% of the estimated annual labour savings the system delivers. The client keeps the other 50% as pure saving. This is a 12-month commitment.

All prices are in AUD and exclude GST.

PRICING RULES:
- Upfront fee: Estimate realistic hours at $400/hr. Don't inflate but don't undercut. Include: requirements analysis, architecture, development, testing, deployment, handover. Round to nearest $500.
- Annual fee: Calculate the labour/cost savings the system replaces → take 50% as the annual fee. Show the working clearly.
- ROI: Based on the annual fee vs annual value delivered. The client should see clear positive ROI from year 1 (since they keep 50% of savings + the upfront is a one-off).
- Be specific about what hours go where in the upfront estimate.
- Be specific about what labour/costs the system replaces in the annual calculation.

OUTPUT FORMAT: Valid JSON only. Structure:
{
  "projectName": "Name",
  "clientCompany": "Company name from context or 'TBD'",
  "commercialContext": "What this system changes for the client's business. Be specific about the problem being solved.",
  "labourAnalysis": {
    "currentProcess": "Describe the current manual/existing process and who does it",
    "hoursPerWeek": 0,
    "hourlyRate": 0,
    "annualLabourCost": 0,
    "additionalCosts": "Any other costs replaced (software, outsourcing, errors, etc)",
    "totalAnnualSavings": 0
  },
  "upfrontFee": {
    "totalHours": 0,
    "hourlyRate": 400,
    "breakdown": [
      {"phase": "Discovery & Design", "hours": 0, "description": "What's included"},
      {"phase": "Development & Integration", "hours": 0, "description": "What's included"},
      {"phase": "Testing & Deployment", "hours": 0, "description": "What's included"},
      {"phase": "Handover & Documentation", "hours": 0, "description": "What's included"}
    ],
    "total": 0
  },
  "annualFee": {
    "calculation": "50% of $X annual savings = $Y",
    "monthlyEquivalent": 0,
    "total": 0,
    "includes": "What ongoing support covers: monitoring, optimisation, updates, support hours, etc"
  },
  "roiIllustration": {
    "annualSavings": 0,
    "annualFee": 0,
    "netAnnualBenefit": 0,
    "roiMultiple": "e.g. 2.0x (client keeps 50% of savings)",
    "paybackOnUpfront": "How many months of net savings to recoup upfront fee",
    "summary": "1-2 sentence ROI statement"
  },
  "timeline": "Estimated delivery timeline from kick-off to live",
  "assumptions": ["Key assumptions that affect pricing"],
  "exclusions": ["What's NOT included in either fee"],
  "validUntil": "30 days from generation"
}

PROJECT DESIGN:
Executive Summary: ${executiveSummary}
Core Workflow: ${coreWorkflow}
Architecture: ${architecture}
Build Effort: ${buildEffort}
Cost-Benefit Analysis: ${costBenefit}
Assumptions: ${assumptions}
Phase 2 Enhancements: ${phase2}
Risks: ${risks}
${extraContext}

Be realistic and commercially credible. Show your working.`;

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
      body: JSON.stringify({
        model,
        max_completion_tokens: 4096,
        messages: [
          { role: 'system', content: 'You are a commercially minded product strategist and value-based pricing advisor. Return valid JSON only. Think in enterprise value terms, anchor price to impact, justify pricing rationally.' },
          { role: 'user', content: prompt }
        ],
        response_format: { type: 'json_object' }
      })
    });

    if (!response.ok) throw new Error('LLM request failed: ' + await response.text());

    const data = await response.json();
    let proposalContent = data.choices[0].message.content;

    // Parse
    let proposal;
    try {
      proposal = JSON.parse(proposalContent);
    } catch(e) {
      // Try extracting JSON from markdown
      const match = proposalContent.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (match) proposal = JSON.parse(match[1]);
      else throw new Error('Failed to parse proposal JSON');
    }

    // Add metadata
    proposal.id = `proposal-${projectId}-${Date.now()}`;
    proposal.projectId = projectId;
    proposal.createdAt = new Date().toISOString();
    proposal.designId = design.id || 'unknown';
    proposal.status = 'draft';

    // Save
    fs.writeFileSync(path.join(PROPOSALS_DIR, proposal.id + '.json'), JSON.stringify(proposal, null, 2));

    generationStatus[projectId] = { type: 'proposal', status: 'done', finishedAt: Date.now() };
    console.log(`Proposal generated for project ${projectId}`);
  } catch(e) {
    console.error('Proposal generation error:', e);
    generationStatus[projectId] = { type: 'proposal', status: 'error', error: e.message };
  }
}

module.exports = router;
module.exports.loadNewestProposal = loadNewestProposal;
module.exports.PROPOSALS_DIR = PROPOSALS_DIR;
module.exports.getEngineBuildId = getEngineBuildId;
