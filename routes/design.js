const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const db = require('../database-adapter');
const auth = require('../auth');
const emails = require('../emails');
const { DESIGNS_DIR, uploadsDir } = require('../helpers/paths');
const { encodeProjectId, resolveProjectId } = require('../helpers/ids');
const { escapeHtml, summarizeRequirements, generateFollowupQuestions } = require('../helpers/formatting');
const { sendMortiEmail } = require('../helpers/email-sender');
const generationStatus = require('../helpers/generation-status');

// Decode hashed IDs in :id route params
router.param('id', (req, res, next, val) => {
  req.params.id = resolveProjectId(val);
  next();
});

// Helper: load newest design for a project
function loadNewestDesign(projectId) {
  const designsDir = DESIGNS_DIR;
  if (!fs.existsSync(designsDir)) return null;
  const candidates = fs.readdirSync(designsDir).filter(f => f.startsWith(`design-${projectId}-`));
  if (candidates.length === 0) return null;
  let newest = candidates[0];
  let newestMtime = fs.statSync(path.join(designsDir, newest)).mtimeMs;
  for (const c of candidates) {
    const m = fs.statSync(path.join(designsDir, c)).mtimeMs;
    if (m > newestMtime) { newest = c; newestMtime = m; }
  }
  return { design: JSON.parse(fs.readFileSync(path.join(designsDir, newest), 'utf8')), file: newest };
}

function saveDesign(design) {
  const designsDir = DESIGNS_DIR;
  fs.mkdirSync(designsDir, { recursive: true });
  fs.writeFileSync(path.join(designsDir, design.id + '.json'), JSON.stringify(design, null, 2));
}

// Sanitise mermaid syntax from LLM output
function sanitiseMermaid(raw) {
  let code = (raw || '').trim();
  code = code.replace(/^```(?:mermaid)?\s*/im, '').replace(/```\s*$/m, '').trim();
  if (!/^(flowchart|graph)\s+(TD|TB|LR|RL|BT)/i.test(code)) {
    code = 'flowchart LR\n' + code;
  }
  code = code.replace(/([^\-])->/g, '$1-->');
  const lines = code.split('\n');
  const sanitised = lines.map(line => {
    return line.replace(/(\b\w+)((?:\[\[|\[\(|\(\[|\[|\(\(|\(|\{))(.*?)((?:\]\]|\)\]|\]\)|\]\)|\)|\}|\]))(?=\s|$|;)/g, (match, id, open, label, close) => {
      let clean = label.replace(/^["']|["']$/g, '').trim();
      clean = '"' + clean.replace(/"/g, "'") + '"';
      return id + open + clean + close;
    });
  });
  code = sanitised.join('\n');
  code = code.replace(/\n{3,}/g, '\n\n');
  return code;
}

function isMermaidValid(code) {
  if (!code) return false;
  if (!/^(flowchart|graph)\s+(TD|TB|LR|RL|BT)/i.test(code)) return false;
  const lines = code.split('\n').filter(l => l.trim() && !l.trim().startsWith('%%'));
  if (lines.length < 3) return false;
  if (!(/-->/.test(code))) return false;
  const opens = (code.match(/\[/g) || []).length;
  const closes = (code.match(/\]/g) || []).length;
  if (Math.abs(opens - closes) > 1) return false;
  return true;
}

// Trigger design extraction
router.post('/admin/projects/:id/extract-design', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const projectId = req.params.id;

  generationStatus[projectId] = { type: 'design', status: 'generating', startedAt: Date.now() };
  res.redirect(`/admin/projects/${encodeProjectId(projectId)}/design`);

  extractDesignAsync(projectId, req.user).catch(err => {
    console.error('Background design extraction failed:', err);
    generationStatus[projectId] = { type: 'design', status: 'error', error: err.message };
  });
});

async function extractDesignAsync(projectId, user) {
  try {
    const sessions = await db.getSessionsByProject(projectId);
    let reqText = '';
    sessions.forEach(s => {
      try {
        const t = JSON.parse(s.transcript || '[]');
        t.forEach(m => reqText += `${m.role}: ${m.text}\n`);
      } catch {}
    });
    const files = await db.getFilesByProject(projectId);
    for (const f of files) {
      let text = '';
      const fname = f.original_name || f.filename;
      const diskPath = path.join(uploadsDir, fname);
      if (fs.existsSync(diskPath)) {
        try {
          const ext = path.extname(fname).toLowerCase();
          if (['.txt', '.md', '.csv', '.json', '.xml', '.yaml', '.yml', '.html', '.css', '.js', '.ts', '.py'].includes(ext)) {
            text = fs.readFileSync(diskPath, 'utf8');
          } else if (['.doc', '.docx'].includes(ext)) {
            try { const mammoth = require('mammoth'); const r = await mammoth.extractRawText({ path: diskPath }); text = r.value; } catch(e) { text = (f.extracted_text || '').trim(); }
          } else if (ext === '.pdf') {
            try { const { PDFParse } = require('pdf-parse'); const buf = new Uint8Array(fs.readFileSync(diskPath)); const parser = new PDFParse(buf); await parser.load(); const r = await parser.getText(); text = r && r.pages ? r.pages.map(p => p.text).join('\n\n') : (typeof r === 'string' ? r : ''); } catch(e) { text = (f.extracted_text || '').trim(); }
          } else {
            text = (f.extracted_text || '').trim();
          }
        } catch(e) { text = (f.extracted_text || '').trim(); }
      } else {
        text = (f.extracted_text || '').trim();
      }
      if (text) {
        if (text.length > 50000) text = text.substring(0, 50000) + '\n\n[...truncated from ' + text.length + ' chars]';
        reqText += `\n\nUPLOADED FILE: ${fname}\n${f.description ? 'Description: ' + f.description + '\n' : ''}Content:\n${text}\n`;
      } else {
        reqText += `\nUPLOADED FILE: ${fname} (no text extracted)\n`;
      }
    }

    const project = await db.getProject(projectId);
    try {
      const adminNotes = JSON.parse(project.admin_notes || '[]');
      if (adminNotes.length > 0) {
        reqText += '\n\nADMIN NOTES (additional context provided by the project administrator):\n';
        adminNotes.forEach(n => { reqText += `- ${n.text}\n`; });
      }
    } catch(e) {}

    let llmDesignMarkdown = '';
    let llmQuestions = generateFollowupQuestions(summarizeRequirements(reqText));
    let designVersion = 1;
    let designStatus = 'draft';
    let designParsedSections = null;
    let designParsedCustomerDesign = null;
    let designParsedEngineDesign = null;
    let designSummary = '';
    let designWorkflows = [];
    let designAssets = [];

    const DESIGN_SECTIONS_SCHEMA = `{
  "summary": "3-5 sentence executive summary: what this system actually is, the core operating loop, what problem it solves, and what it is NOT.",
  "customerDesign": {
    "ExecutiveSummary": "Plain English explanation of what this system is. What problem it solves, for whom, and the core value proposition. 2-4 paragraphs max. Write for a business stakeholder, not an engineer.",
    "HowItWorks": "Step-by-step operational flow from the USER'S perspective as a NUMBERED LIST, grouped by workflow where applicable. Each step: a short bold title, then 1-2 sentences describing what happens. Focus on what the user sees/does, not internal plumbing. If there are multiple workflows, label them clearly (e.g., 'Workflow 1: New Lead Intake'). Keep each workflow to 4-8 steps max. Example format: 1. **Submit Request** — You upload your brief and the system extracts key requirements automatically.",
    "WhatYouGet": "Concrete deliverables and outcomes as a BULLETED LIST. What the customer will actually receive — screens, dashboards, automations, reports, integrations. Be specific and tangible. Include any key metrics or KPIs the system will track.",
    "WhatWeNeedFromYou": "BULLETED LIST of everything needed from the customer to proceed: access credentials, decisions to make, content to provide, approvals needed, stakeholder availability. Tag each as (Before Build), (During Build), or (Before Launch).",
    "TimelineAndInvestment": "Phases with timeline and what gets delivered in each phase. Include complexity rating (Low/Medium/High) and rough effort estimate. Be practical and specific. If cost data was not provided, note this clearly.",
    "AutomatedVsManual": "TWO LISTS: 'The System Handles' and 'You Still Control'. For each item: what it is and why it's in that category. Focus on the strategic value of what stays human (decisions, approvals, quality control) vs what gets automated (repetition, data entry, notifications)."
  },
  "engineDesign": {
    "TechnicalArchitecture": "Architecture as a BULLETED LIST of components. For each: component name, specific tool/service recommended, rationale, and how it connects to other components. Include hosting, deployment, and a 'NOT required for MVP' list. Avoid microservices and enterprise over-engineering.",
    "DataModel": "BULLETED LIST of entities. For each: **Entity Name** — all key fields with types/descriptions, relationships to other entities, purpose in the system. Include example values where helpful.",
    "IntegrationsAndAPIs": "COMPREHENSIVE list of all external services, APIs, webhooks needed. For each: service name, what it's used for, endpoint/auth details if known, cost tier, and tag as (Critical) or (Optional). Include: APIs & Endpoints (URLs, methods, auth, request/response formats, rate limits), Integration Specifics (webhook formats, callback URLs, polling intervals), Configuration (env vars, feature flags). Quote directly from source material where possible.",
    "BuildSpecification": "DETAILED build specification ORGANISED BY WORKFLOW. For each workflow from the 'workflows' array, provide a numbered step list. This is the engineering team's primary reference. For EACH step include: (a) **Bold step name**, (b) Detailed description — inputs, processing, outputs, (c) Data flow — what comes in and goes out, (d) Error handling — what happens if this step fails, (e) Specific tools/services used, (f) Business rules, conditions, and logic that apply, (g) Human control/review points if applicable. There is NO length limit — be exhaustive. Also include: assumptions made (mark with [ASSUMPTION]), dependencies between workflows, and any technical details extracted from requirements (field names, data types, regex patterns, code snippets, URLs, compliance requirements). IMPORTANT: If a step involves waiting for an external event (webhook, callback, human action), that is a WORKFLOW BOUNDARY — the next steps belong to a separate workflow.",
    "RiskRegister": "BULLETED LIST of realistic risks. For each: **Risk** — likelihood, impact, detailed mitigation strategy, and who is responsible. Include technical risks, dependency risks, and timeline risks. No theatrical or enterprise-only risks."
  },
  "workflows": [
    {"id": "wf-1", "name": "Descriptive workflow name", "trigger": "What kicks this workflow off (webhook, schedule, manual, form submission, email, etc.)", "summary": "1-2 sentence description of what this workflow does end-to-end", "steps": "Numbered list of steps in this specific workflow — inputs, processing, outputs for each step", "outputsTo": "What happens at the end — triggers another workflow, sends notification, updates sheet, etc."}
  ],
  "assets": [
    {"id": "asset-1", "name": "Descriptive name", "type": "google-sheet | google-script | web-app | web-form | static-page | google-doc | dashboard", "purpose": "What this asset is for and how it connects to the automation", "buildNotes": "Specific instructions for building — columns/structure for sheets, functionality for apps, content for docs, fields for forms", "linkedToWorkflows": ["wf-1"], "buildOrIntegrate": "build | integrate | question", "integrationNotes": "If 'question' — what we need to ask the customer about their existing infrastructure"}
  ],
  "questions": [
    {"id": 1, "text": "Specific question about a gap or ambiguity", "assumption": "What we'll assume if unanswered"}
  ]
}`;

    const DESIGN_RULES = `RULES:
- You are a pragmatic product architect. The requirements may be verbose, repetitive, or over-engineered. Your job is to SYNTHESIZE them into a commercially credible MVP design.
- The output has TWO audiences: customerDesign is for the business stakeholder (clear, non-technical, outcome-focused), engineDesign is for the build team (detailed, technical, exhaustive).
- Extract the true business objective. Preserve critical strategic control points (human decisions, approval loops, segmentation logic).
- Remove premature scaling, infrastructure complexity, and architectural over-design.
- Focus on a system that can realistically be built by a small team in under 4 weeks.
- Use off-the-shelf tools where possible. Assume early-stage deployment with limited users unless otherwise specified.
- Do NOT restate the requirements. Interpret them and produce a buildable design.
- ALL section values MUST be plain text strings (no nested JSON objects). Use "- " for lists, "1. " for sequences.
- Reference the specific tools, platforms, and workflows mentioned in the conversation.
- Where vague, make a reasonable assumption and mark it with [ASSUMPTION].

TONE:
- customerDesign: Friendly, clear, confident. Write for a founder or business owner. No jargon. Short sentences. Focus on outcomes and value.
- engineDesign: Precise, detailed, technical. Write for a developer who needs to build this. Include every relevant detail.

LENGTH:
- customerDesign sections should be CONCISE — the customer should be able to read the entire design in 5 minutes. HowItWorks should be 4-8 steps max.
- engineDesign sections have NO length limit. BuildSpecification in particular should be comprehensive — this is what the build team relies on most.

BUILD PLATFORM — MORTI ENGINE:
- If the project is a workflow automation, the Morti Engine uses **Pipedream Connect** as the orchestration layer. If the project is NOT a workflow automation (e.g. a web app, mobile app, data platform, AI tool), propose the appropriate external technology stack instead — do NOT force Pipedream where it doesn't fit.
- **Pipedream Connect**: Managed auth via OAuth — customer connects their accounts (Google, OpenAI, Slack, etc.) and the engine invokes actions on their behalf. 2700+ app integrations. No credential sharing needed.
- Pipedream workflows are deployed as step-by-step pipelines. Each step is deployed, tested with real data, and advanced individually.
- Each customer gets isolated multi-tenant deployment via Pipedream external_user_id.
- For each automation workflow, the engineDesign.BuildSpecification should describe steps as a pipeline: inputs, processing, outputs, and which app/API each step uses.
- The TechnicalArchitecture section should specify: (a) a Pipedream automation pipeline, (b) a web app with Pipedream automations supporting it, (c) an external/custom build with appropriate technology, or a combination.

WORKFLOWS — CRITICAL:
- A project typically contains MULTIPLE distinct workflows, not one monolithic pipeline. Your #1 job is to identify and separate them.
- Each workflow has a distinct TRIGGER (what starts it) and a distinct OUTCOME (what it produces).
- WEBHOOK RULE: If a workflow has a webhook trigger waiting midway through a process (e.g., "wait for approval callback", "wait for payment confirmation"), that webhook is the START of a NEW workflow. Split it there. The first workflow ends by sending/triggering whatever creates the webhook event. The second workflow starts when that webhook fires.
- Examples of workflow boundaries: form submission → processing pipeline, scheduled report generation, webhook from payment provider, email received trigger, manual admin action.
- Name each workflow clearly (e.g., "New Lead Intake", "Weekly Report Generation", "Payment Confirmation Handler").
- Show how workflows connect to each other (outputsTo field).

ASSETS — REQUIRED RESOURCES:
- Identify any assets that need to exist BEFORE or ALONGSIDE the automation workflows. These are NOT automation steps — they are resources the workflows depend on.
- Asset types: google-sheet (tracking/data storage), google-script (Apps Script custom logic/web apps), web-app (frontend input pages, dashboards), web-form (data collection forms), static-page (landing pages, confirmation pages), google-doc (templates, documents), dashboard (reporting/monitoring views).
- For each asset, specify: a clear name, the type, what it's for (purpose), specific build instructions (buildNotes — e.g. column names for sheets, page functionality for apps, fields for forms), and which workflows use it (linkedToWorkflows).
- WEB ASSETS ARE CRITICAL: Any mention of input forms, portals, dashboards, customer-facing pages, or data entry interfaces MUST be identified as assets.
- For EVERY web asset (web-app, web-form, dashboard, static-page), you MUST flag whether to BUILD it fresh or INTEGRATE with the customer's existing web infrastructure (website, CRM, portal). Set buildOrIntegrate to "question" and write a specific integrationNotes question if unclear.
- Examples: "A Google Sheet to track blog draft status", "A web form for new client intake", "A customer dashboard showing project status", "A Google Doc template for proposals".
- If the project mentions spreadsheets, forms, dashboards, tracking, input pages, portals, or templates — these are assets.
- Generate a QUESTION for each web asset where it's unclear whether the customer wants us to build it or integrate with their existing systems. E.g., "You mentioned needing an intake form — should we build a standalone web form, or do you have an existing website/portal where this should be embedded?"

DESIGN PRINCIPLES:
- Humans steer; systems automate repetition.
- Prove the loop before scaling.
- Use simplicity as a strategic advantage.
- Remove anything that does not directly create user value in MVP.`;

    const buildPrompt = (context, prevAnswers, previousDesign) => {
      if (!previousDesign) {
        return `You are a pragmatic product architect and systems designer. You are given a raw requirements dataset from a client conversation. Your task is to synthesize those requirements into a commercially credible MVP design document.

OUTPUT FORMAT: Valid JSON only. No markdown wrapping. Structure:
${DESIGN_SECTIONS_SCHEMA}

${DESIGN_RULES}

QUESTIONS RULES (FIRST EXTRACTION):
- Generate questions ONLY for genuinely missing critical information that would block a small team from building this in 4 weeks.
- Questions MUST reference specific details from the conversation.
- BAD: "Any branding guidelines?", "What data sources?" — generic filler.
- GOOD: "You mentioned LinkedIn Sales Navigator — do you need real-time monitoring or is a daily batch sync sufficient for MVP?"
- MANDATORY: If the requirements do NOT include cost/value information (current process cost, expected ROI, human labour equivalent), you MUST include at least one question about this. Examples:
  - "What does the current process cost your team in time or money each month?"
  - "If you were to handle [specific workflow] manually with staff, roughly what would that cost?"
  - "What's the expected value or saving this system would deliver in the first 12 months?"
  This is required before a proposal can be generated.
- Maximum 5 questions. If the conversation covers everything needed for MVP, return an EMPTY array [].
- Each question needs a unique sequential id starting from 1.

RAW REQUIREMENTS (conversation & files):
${context}`;
      } else {
        return `You are a pragmatic product architect UPDATING an existing MVP design. A previous design already exists. Your job is to:

1. READ THE DESIGN CHAT FEEDBACK FIRST — this is the admin's explicit instructions for what to change. This is your #1 priority. Every piece of admin feedback MUST be reflected in the updated design.
2. START with the previous design as the baseline — preserve all existing content that wasn't flagged for change.
3. INCORPORATE new information: chat feedback, answered questions, admin notes, updated requirements.
4. REFINE sections affected by the new information.
5. DO NOT regenerate sections that haven't changed AND weren't discussed in chat feedback.
6. DO NOT ask new questions unless the new information reveals a genuinely critical gap for MVP delivery.

OUTPUT FORMAT: Valid JSON only. No markdown wrapping. Same structure:
${DESIGN_SECTIONS_SCHEMA}

${DESIGN_RULES}

QUESTIONS RULES (REFRESH — STRICT):
- Only ask NEW questions if the new information reveals a critical gap that blocks MVP build.
- Do NOT re-ask answered questions. Do NOT ask follow-ups to satisfactory answers.
- Prefer making an [ASSUMPTION] over asking another question.
- MANDATORY: If the CostBenefitAnalysis section still lacks concrete cost/value data (current process cost, ROI estimate, human labour equivalent), include a question about this. Proposals cannot be generated without cost justification.
- Maximum 3 new questions. Return EMPTY array [] if nothing critical is missing.
- If previous questions were answered satisfactorily, there should be ZERO new questions.

PREVIOUS DESIGN (baseline — preserve, update where new info applies):
${JSON.stringify({ customerDesign: previousDesign.customerDesign || null, engineDesign: previousDesign.engineDesign || null, sections: (!previousDesign.customerDesign && previousDesign.sections) ? previousDesign.sections : undefined }, null, 2).substring(0, 20000)}

Previous Summary: ${previousDesign.summary || 'None'}

ANSWERED QUESTIONS (incorporate into design, do NOT re-ask):
${prevAnswers || 'None'}

NEW INFORMATION SINCE LAST DESIGN:
${context}`;
      }
    };

    let prevAnswersText = '';
    let previousDesign = null;
    try {
      const prevResult = loadNewestDesign(projectId);
      if (prevResult && prevResult.design) {
        previousDesign = prevResult.design;
        const prev = prevResult.design;
        if (prev.answers && prev.answers.length > 0) {
          prevAnswersText += prev.answers.map(a => `Q: ${a.question}\nA (admin): ${a.answer}`).join('\n\n');
        }
        if (prev.customerAnswers && prev.customerAnswers.length > 0) {
          prevAnswersText += '\n\n' + prev.customerAnswers.map(a => `Q: ${a.question}\nA (customer - ${a.from}): ${a.answer}`).join('\n\n');
        }
      }
    } catch(e) { console.warn('Failed to load previous design:', e.message); }

    let promptContext = reqText.substring(0, 60000);
    if (previousDesign) {
      const newInfo = [];
      if (previousDesign.chat && previousDesign.chat.length > 0) {
        const chatFeedback = previousDesign.chat
          .filter(c => (c.role === 'user' || c.role === 'assistant') || (c.from || c.text))
          .map(c => {
            const isAdmin = c.role === 'user' || (c.from && c.from !== 'ai' && c.from !== 'assistant');
            const text = c.content || c.text || '';
            return text ? `${isAdmin ? 'ADMIN FEEDBACK' : 'AI RESPONSE'}: ${text}` : '';
          })
          .filter(Boolean)
          .join('\n\n');
        if (chatFeedback) {
          newInfo.push('⚠️ HIGHEST PRIORITY — DESIGN CHAT FEEDBACK (the admin explicitly discussed these changes and EXPECTS them in the refreshed design. You MUST incorporate every piece of admin feedback below. If admin said to change something, change it.):\n\n' + chatFeedback);
        }
      }
      try {
        const adminNotes = JSON.parse(project.admin_notes || '[]');
        if (adminNotes.length > 0) {
          newInfo.push('ADMIN NOTES (incorporate these):\n' + adminNotes.map(n => `- ${n.text}`).join('\n'));
        }
      } catch(e) {}
      if (prevAnswersText) newInfo.push('ANSWERED QUESTIONS:\n' + prevAnswersText);
      if (previousDesign.acceptedAssumptions && previousDesign.acceptedAssumptions.length > 0) {
        newInfo.push('ACCEPTED ASSUMPTIONS (incorporate these as decisions, do NOT re-ask):\n' +
          previousDesign.acceptedAssumptions.map(a => `- Q: ${a.question} → Assumption accepted: ${a.assumption}`).join('\n'));
      }
      newInfo.push('FULL PROJECT TRANSCRIPT (background reference only — chat feedback above takes priority over anything here):\n' + reqText.substring(0, 40000));
      promptContext = newInfo.join('\n\n---\n\n');
    }

    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    let rawLlmOutput = '';
    if (OPENAI_KEY) {
      try {
        const prompt = buildPrompt(promptContext, prevAnswersText, previousDesign);
        let content = '';

        const model = process.env.LLM_MODEL || 'gpt-5.2';
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
          body: JSON.stringify({ model, max_completion_tokens: 32000, messages: [
            { role: 'system', content: 'You are a senior solutions architect and business analyst. You produce detailed, actionable solution designs. Output valid JSON only, no markdown wrapping.' },
            { role: 'user', content: prompt }
          ]})
        });
        if (resp.ok) {
          const data = await resp.json();
          content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
          console.log('Design LLM response: model=' + model + ', length=' + (content || '').length);
        } else {
          const errText = await resp.text().catch(()=>'');
          console.error('LLM call failed:', resp.status, errText);
          throw new Error('LLM API error (' + resp.status + '): ' + (errText || 'Unknown error'));
        }

        if (content) {
          rawLlmOutput = content;

          // Try to parse JSON, with recovery for truncated responses
          const tryParseJSON = (text) => {
            let cleanContent = text;
            if (cleanContent.includes('```json')) {
              cleanContent = cleanContent.replace(/```json\s*/g, '').replace(/```/g, '');
            }
            const jsonStart = cleanContent.indexOf('{');
            const jsonText = jsonStart >= 0 ? cleanContent.slice(jsonStart) : cleanContent;

            // First try direct parse
            try { return JSON.parse(jsonText); } catch(e) { /* continue to recovery */ }

            // Truncated JSON recovery: close open brackets/braces
            let recovered = jsonText;
            const stack = [];
            let inString = false, escaped = false;
            for (let i = 0; i < recovered.length; i++) {
              const ch = recovered[i];
              if (escaped) { escaped = false; continue; }
              if (ch === '\\') { escaped = true; continue; }
              if (ch === '"' && !escaped) { inString = !inString; continue; }
              if (inString) continue;
              if (ch === '{') stack.push('}');
              else if (ch === '[') stack.push(']');
              else if (ch === '}' || ch === ']') stack.pop();
            }
            // If we're inside a string, close it
            if (inString) recovered += '"';
            // Close any open brackets/braces
            while (stack.length > 0) recovered += stack.pop();

            try {
              const result = JSON.parse(recovered);
              console.warn('⚠️ Design JSON was truncated — recovered by closing ' + stack.length + ' open brackets');
              return result;
            } catch(e2) { throw e2; }
          };

          try {
            const parsed = tryParseJSON(content);
            console.log('Design LLM parsed keys:', Object.keys(parsed));
            console.log('  customerDesign:', parsed.customerDesign ? Object.keys(parsed.customerDesign) : 'null');
            console.log('  engineDesign:', parsed.engineDesign ? Object.keys(parsed.engineDesign) : 'null');
            console.log('  workflows:', Array.isArray(parsed.workflows) ? parsed.workflows.length : 'null');
            console.log('  assets:', Array.isArray(parsed.assets) ? parsed.assets.length : 'null');

            // Flatten structured objects to markdown strings.
            // Handles arrays of step-like objects (title+description) → "1. **Title** — desc" format
            const flattenObj = (obj, prefix = '') => {
              let out = '';
              if (Array.isArray(obj)) {
                // Check if items are step-like objects with title/name + description/desc
                const isStepArray = obj.length > 0 && typeof obj[0] === 'object' && obj[0] !== null &&
                  (obj[0].title || obj[0].name || obj[0].step_name || obj[0].stepName);
                if (isStepArray) {
                  obj.forEach((item, i) => {
                    const title = item.title || item.name || item.step_name || item.stepName || `Step ${i+1}`;
                    const desc = item.description || item.desc || item.details || '';
                    out += `${i+1}. **${title}** — ${desc}\n`;
                  });
                } else {
                  obj.forEach((item, i) => {
                    if (typeof item === 'object') out += flattenObj(item, `${i+1}. `);
                    else out += `- ${item}\n`;
                  });
                }
              } else if (typeof obj === 'object' && obj !== null) {
                for (const [k, v] of Object.entries(obj)) {
                  if (typeof v === 'object') { out += `\n${prefix}${k}:\n${flattenObj(v, '  ')}`; }
                  else { out += `${prefix}- ${k}: ${v}\n`; }
                }
              }
              return out;
            };
            const flattenSection = (val) => {
              if (typeof val === 'string') return val;
              if (typeof val === 'object') return flattenObj(val);
              return String(val);
            };

            let parsedCustomerDesign = null;
            let parsedEngineDesign = null;

            if (parsed.customerDesign && typeof parsed.customerDesign === 'object') {
              parsedCustomerDesign = {};
              for (const [key, val] of Object.entries(parsed.customerDesign)) {
                parsedCustomerDesign[key] = flattenSection(val);
              }
            }
            if (parsed.engineDesign && typeof parsed.engineDesign === 'object') {
              parsedEngineDesign = {};
              for (const [key, val] of Object.entries(parsed.engineDesign)) {
                parsedEngineDesign[key] = flattenSection(val);
              }
            }

            if (parsed.design && typeof parsed.design === 'object' && !parsedCustomerDesign) {
              const flatDesign = {};
              for (const [key, val] of Object.entries(parsed.design)) {
                flatDesign[key] = flattenSection(val);
              }
              designParsedSections = flatDesign;
            } else if (typeof parsed.design === 'string' && !parsedCustomerDesign) {
              llmDesignMarkdown = parsed.design;
            }

            if (parsedCustomerDesign || parsedEngineDesign) {
              designParsedSections = { ...(parsedCustomerDesign || {}), ...(parsedEngineDesign || {}) };
            }

            if (designParsedSections) {
              let md = '';
              for (const [section, body] of Object.entries(designParsedSections)) {
                const title = section.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase()).trim();
                md += `## ${title}\n\n${body}\n\n`;
              }
              llmDesignMarkdown = md;
            }

            if (parsed.summary) designSummary = parsed.summary;
            if (parsed.questions && Array.isArray(parsed.questions)) llmQuestions = parsed.questions;
            if (parsed.workflows && Array.isArray(parsed.workflows)) {
              // Ensure workflow steps are strings (LLM may return arrays/objects)
              designWorkflows = parsed.workflows.map(wf => ({
                ...wf,
                steps: (typeof wf.steps === 'string') ? wf.steps : flattenSection(wf.steps)
              }));
            }
            if (parsed.assets && Array.isArray(parsed.assets)) designAssets = parsed.assets;
            if (parsedCustomerDesign) designParsedCustomerDesign = parsedCustomerDesign;
            if (parsedEngineDesign) designParsedEngineDesign = parsedEngineDesign;
          } catch (e) {
            console.warn('JSON parse failed, using raw content:', e.message);
            llmDesignMarkdown = content || '';
          }
        }
      } catch (e) {
        console.error('LLM call error:', e.message);
        throw new Error('Design extraction failed: ' + e.message);
      }
    } else {
      throw new Error('OPENAI_API_KEY not configured — cannot extract design');
    }

    llmDesignMarkdown = llmDesignMarkdown.replace(/^ *(user|ai|assistant):.*$/gmi, '').trim();

    function mdToHtml(md){
      if(!md) return '';
      let out = String(md || '');
      out = out.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      out = out.replace(/^### (.*)$/gm, '<h3>$1</h3>');
      out = out.replace(/^## (.*)$/gm, '<h2>$1</h2>');
      out = out.replace(/^# (.*)$/gm, '<h1>$1</h1>');
      const paras = out.split(/\n\n+/).map(p=>p.trim()).filter(Boolean);
      out = paras.map(p => '<p>' + p.replace(/\n/g,'<br/>') + '</p>').join('\n');
      return out;
    }

    try {
      const designsDirCheck = DESIGNS_DIR;
      if (fs.existsSync(designsDirCheck)) {
        const existing = fs.readdirSync(designsDirCheck).filter(f => f.startsWith(`design-${projectId}-`));
        if (existing.length > 0) {
          let newest = existing[0];
          let newestMtime = fs.statSync(path.join(designsDirCheck, newest)).mtimeMs;
          for (const c of existing) {
            const m = fs.statSync(path.join(designsDirCheck, c)).mtimeMs;
            if (m > newestMtime) { newest = c; newestMtime = m; }
          }
          try {
            const prev = JSON.parse(fs.readFileSync(path.join(designsDirCheck, newest), 'utf8'));
            if (prev && prev.version) designVersion = prev.version + 1;
          } catch(e){}
        }
      }
    } catch(e){}

    const design = {
      id: `design-${projectId}-${Date.now()}`,
      projectId,
      createdAt: new Date().toISOString(),
      owner: user.email,
      version: designVersion,
      status: designStatus,
      summary: designSummary,
      designMarkdown: llmDesignMarkdown,
      designHtml: mdToHtml(llmDesignMarkdown),
      sections: designParsedSections,
      customerDesign: designParsedCustomerDesign,
      engineDesign: designParsedEngineDesign,
      workflows: designWorkflows,
      assets: designAssets,
      questions: llmQuestions,
      chat: [],
      answers: [],
      customerAnswers: [],
      raw_output: rawLlmOutput
    };

    try {
      const prevResult = loadNewestDesign(projectId);
      if (prevResult && prevResult.design) {
        const prev = prevResult.design;
        if (prev.answers && prev.answers.length > 0) design.answers = prev.answers;
        if (prev.customerAnswers && prev.customerAnswers.length > 0) design.customerAnswers = prev.customerAnswers;
        if (prev.chat && prev.chat.length > 0) design.chat = prev.chat;
        if (prev.published) { design.published = prev.published; design.publishedAt = prev.publishedAt; }
        if (prev.acceptedAssumptions && prev.acceptedAssumptions.length > 0) design.acceptedAssumptions = prev.acceptedAssumptions;
        if (prev.flowchart) design.flowchart = prev.flowchart;
        if (prev.coreWorkflowFlowchart) design.coreWorkflowFlowchart = prev.coreWorkflowFlowchart;
      }
    } catch(e) {}

    try {
      if (design.designMarkdown && String(design.designMarkdown).trim().startsWith('```json')) {
        const jsonText = String(design.designMarkdown).replace(/```json\s*|```/g, '').trim();
        try {
          const parsed = JSON.parse(jsonText);
          if (parsed.questions && Array.isArray(parsed.questions)) design.questions = parsed.questions;
          if (parsed.design) {
            design.designHtml = '';
            for (const [k,v] of Object.entries(parsed.design)) {
              design.designHtml += `<h3>${escapeHtml(k)}</h3><p>${escapeHtml(String(v))}</p>`;
            }
          }
          if (parsed.raw_output) design.raw_output = parsed.raw_output;
        } catch(e) { console.warn('Failed to parse design JSON output:', e.message); }
      }
    } catch(e) {}

    const designsDir = DESIGNS_DIR;
    fs.mkdirSync(designsDir, { recursive: true });
    fs.writeFileSync(path.join(designsDir, design.id + '.json'), JSON.stringify(design, null, 2));

    try {
      await db.updateProjectDesignQuestions(projectId, JSON.stringify(design.questions || []));
    } catch(e) { console.warn('Failed to update project.design_questions', e.message); }

    generationStatus[projectId] = { type: 'design', status: 'done', finishedAt: Date.now() };
    console.log(`✅ Design extracted for project ${projectId}`);
  } catch (e) {
    console.error('Extract design error:', e);
    generationStatus[projectId] = { type: 'design', status: 'error', error: e.message };
  }
}

// View design (admin)
router.get('/admin/projects/:id/design', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    const projectName = (project && project.name) || projectId;
    const genStatus = generationStatus[projectId];
    const isGenerating = genStatus && genStatus.type === 'design' && genStatus.status === 'generating';

    const designsDir = DESIGNS_DIR;
    const candidates = (fs.existsSync(designsDir) ? fs.readdirSync(designsDir) : []).filter(f => f.startsWith(`design-${projectId}-`));

    if (candidates.length === 0) {
      if (isGenerating) {
        return res.render('admin/project-design', { user: req.user, projectId, projectName, design: null, generating: true, title: projectName + ' - Design' });
      }
      if (genStatus && genStatus.status === 'error') {
        return res.render('admin/project-design', { user: req.user, projectId, projectName, design: null, generating: false, genError: genStatus.error, title: projectName + ' - Design' });
      }
      return res.status(404).send('No design for project');
    }
    let newest = candidates[0];
    let newestMtime = fs.statSync(path.join(designsDir, newest)).mtimeMs;
    for (const c of candidates) {
      const m = fs.statSync(path.join(designsDir, c)).mtimeMs;
      if (m > newestMtime) { newest = c; newestMtime = m; }
    }
    const design = JSON.parse(fs.readFileSync(path.join(designsDir, newest), 'utf8'));
    try {
      if (design.designMarkdown && design.designMarkdown.trim().startsWith('```json')) {
        const jsonText = design.designMarkdown.replace(/```json\s*|```/g, '').trim();
        try {
          const parsed = JSON.parse(jsonText);
          if (parsed && parsed.design) {
            const sections = parsed.design;
            let html = '';
            if (parsed.summary) html += `<h3>Summary</h3><p>${escapeHtml(parsed.summary)}</p>`;
            for (const [k,v] of Object.entries(sections)) {
              html += `<h3>${escapeHtml(k)}</h3><p>${escapeHtml(v)}</p>`;
            }
            design.designHtml = html;
          }
        } catch(e) {}
      }
    } catch(e) {}
    if (design.sentToEngineAt && design.enginePlanId) {
      try {
        const engineUrl = process.env.ENGINE_API_URL;
        const engineSecret = process.env.ENGINE_API_SECRET;
        if (engineUrl && engineSecret) {
          const checkRes = await fetch(`${engineUrl}/api/builds/${design.enginePlanId}/exists`, {
            headers: { 'Authorization': `Bearer ${engineSecret}` },
            signal: AbortSignal.timeout(3000)
          });
          if (checkRes.ok) {
            const checkData = await checkRes.json();
            if (!checkData.exists) {
              delete design.enginePlanId;
              delete design.engineBuildId;
              saveDesign(design);
            }
          }
        }
      } catch (e) {}
    }

    res.render('admin/project-design', { user: req.user, projectId, projectName, design, generating: isGenerating, title: projectName + ' - Design' });
  } catch (e) {
    console.error('Get design error:', e);
    res.status(500).send('Failed to load design');
  }
});

// Generate mermaid flowchart
router.post('/admin/projects/:id/design/flowchart', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const result = loadNewestDesign(req.params.id);
    if (!result) return res.status(404).json({ error: 'No design found' });
    const { design } = result;

    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (!OPENAI_KEY) return res.status(500).json({ error: 'OpenAI API key not configured' });

    const sections = design.sections || {};
    const designContext = JSON.stringify({ summary: design.summary, customerDesign: design.customerDesign, engineDesign: design.engineDesign, sections }, null, 2);

    const prompt = `You are creating a SIMPLE USER JOURNEY FLOWCHART that a non-technical client can look at and say "yes, that's how it should work".

This is NOT a technical architecture diagram. It shows the logical flow from the user's perspective — what happens step by step when someone uses the system.

STRICT MERMAID SYNTAX RULES — follow these exactly:
1. First line MUST be: flowchart TD
2. EVERY node label MUST be wrapped in double quotes: A["My Label"]
3. Arrows MUST use -->  (two dashes + angle bracket). For labeled arrows: A -->|"label"| B
4. Node shapes: ["Rectangle"] for actions, {"Diamond"} for decisions, (["Stadium"]) for start/end
5. Node IDs must be simple alphanumeric: A, B, C1 — no spaces or special chars in IDs
6. NO semicolons at end of lines
7. NO markdown fences — return raw mermaid code only

VALID EXAMPLE:
flowchart TD
  A(["User visits website"])
  B["Fills in project details"]
  C{"Approved?"}
  D["Receives confirmation email"]
  E["Starts using dashboard"]
  F["Admin reviews request"]
  A --> B
  B --> F
  F --> C
  C -->|"Yes"| D
  D --> E
  C -->|"No"| G["Notified of changes needed"]
  G --> B

INVALID (do NOT do these):
- A[My Label]  ← missing quotes around label
- A -> B  ← wrong arrow, must be -->
- \`\`\`mermaid  ← no code fences

Rules for content:
- Write labels in plain English from the user's perspective (e.g. "Customer uploads invoice" not "POST /api/invoices")
- NO technical jargon — no APIs, databases, servers, endpoints, or system components
- Show the logical workflow: what the user does, what happens next, and any decision points
- 6-12 nodes maximum — keep it simple and readable
- Use decision diamonds for yes/no branching points
- The flow should tell a story a client can follow

Design:
${designContext.substring(0, 12000)}`;

    const generateFlowchart = async (extraContext = '') => {
      const resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
        body: JSON.stringify({
          model: 'gpt-4.1',
          max_completion_tokens: 2000,
          messages: [
            { role: 'system', content: 'You generate simple, non-technical user journey flowcharts in valid Mermaid syntax. Write labels in plain English a client can understand. Return ONLY raw mermaid code. No markdown, no explanation. Every node label must be in double quotes.' },
            { role: 'user', content: prompt + extraContext }
          ]
        })
      });
      if (!resp.ok) throw new Error('OpenAI API returned ' + resp.status);
      const data = await resp.json();
      return (data.choices[0].message.content || '').trim();
    };

    let raw = await generateFlowchart();
    let mermaid = sanitiseMermaid(raw);

    if (!isMermaidValid(mermaid)) {
      console.warn('Flowchart first attempt failed validation, retrying...');
      const retryContext = `\n\nPREVIOUS ATTEMPT WAS INVALID. The output had syntax errors. Common issues: missing quotes around labels, wrong arrow syntax, or missing flowchart header. Please try again following the syntax rules exactly. Here was the broken output for reference:\n${raw.substring(0, 1000)}`;
      raw = await generateFlowchart(retryContext);
      mermaid = sanitiseMermaid(raw);
    }

    try {
      const result2 = loadNewestDesign(req.params.id);
      if (result2) {
        result2.design.flowchart = mermaid;
        saveDesign(result2.design);
      }
    } catch(e) { console.warn('Failed to save flowchart to design:', e.message); }

    res.json({ mermaid });
  } catch (e) { console.error('Flowchart error', e); res.status(500).json({ error: 'Failed to generate flowchart: ' + e.message }); }
});

// Design chat
router.post('/admin/projects/:id/design/chat', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const { designId, text } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Design not found' });
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    const userEntry = { from: req.user.email, text, ts: new Date().toISOString() };
    design.chat = design.chat || [];
    design.chat.push(userEntry);

    let aiText = '';
    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (OPENAI_KEY) {
      try {
        const designContext = JSON.stringify({ summary: design.summary, customerDesign: design.customerDesign, engineDesign: design.engineDesign, sections: design.sections, questions: design.questions, answers: design.answers }, null, 2).substring(0, 10000);
        const chatHistory = (design.chat || []).slice(-10).map(c => ({
          role: c.from === 'AI Assistant' ? 'assistant' : 'user',
          content: c.text
        }));
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
          body: JSON.stringify({
            model: 'gpt-4.1-mini',
            max_completion_tokens: 1500,
            messages: [
              { role: 'system', content: `You are a helpful solutions architect assistant. The user is discussing a solution design before publishing it to a customer. Help them refine, clarify, or improve the design. Be concise and actionable.\n\nDesign context:\n${designContext}` },
              ...chatHistory
            ]
          })
        });
        if (resp.ok) {
          const data = await resp.json();
          aiText = (data.choices[0].message.content || '').trim();
        } else {
          aiText = '(AI response failed — status ' + resp.status + ')';
        }
      } catch (e) {
        aiText = '(AI error: ' + e.message + ')';
      }
    } else {
      aiText = '(OpenAI API key not configured)';
    }

    const aiEntry = { from: 'AI Assistant', text: aiText, ts: new Date().toISOString() };
    design.chat.push(aiEntry);
    fs.writeFileSync(filePath, JSON.stringify(design, null, 2));

    res.json({ userMessage: userEntry, aiMessage: aiEntry });
  } catch (e) {
    console.error('Design chat error:', e);
    res.status(500).json({ error: 'Chat failed: ' + e.message });
  }
});

// Save answers to design questions
router.post('/admin/projects/:id/design/answer', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const { designId, question, answer } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).send('Design not found');
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    design.answers = design.answers || [];
    design.answers.push({ question, answer, from: req.user.email, ts: new Date().toISOString() });
    fs.writeFileSync(filePath, JSON.stringify(design, null, 2));

    try { await db.appendSessionMessageSafe(projectId, { role: 'admin', text: `Answer: ${question} -> ${answer}` }); } catch (e) { console.warn('appendSessionMessageSafe failed:', e.message); }

    res.redirect(`/admin/projects/${encodeProjectId(projectId)}/design?message=Answer+saved`);
  } catch (e) {
    console.error('Design answer error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/design?error=Save+failed`);
  }
});

// Publish design
router.post('/admin/projects/:id/design/publish', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const result = loadNewestDesign(req.params.id);
    if (!result) return res.status(404).send('No design found');
    const { design } = result;
    design.published = true;
    design.publishedAt = new Date().toISOString();
    saveDesign(design);

    (async () => {
      try {
        const project = await db.getProject(req.params.id);
        if (project) {
          const owner = await db.getUserById(project.user_id);
          if (owner && owner.email) {
            const mail = emails.designReadyEmail(project.name, req.params.id);
            await sendMortiEmail(owner.email, mail.subject, mail.html);
          }
        }
      } catch (e) { console.error('[Email] Design ready notification failed:', e.message); }
    })();

    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/design?message=Design+published`);
  } catch (e) {
    console.error('Publish error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/design?error=Publish+failed`);
  }
});

// Admin notes
router.post('/admin/projects/:id/notes', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const { note } = req.body;
    if (!note || !note.trim()) return res.redirect(`/admin/projects/${encodeProjectId(projectId)}`);
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).send('Project not found');
    let notes = [];
    try { notes = JSON.parse(project.admin_notes || '[]'); } catch(e) {}
    notes.push({ text: note.trim(), from: req.user.email, ts: new Date().toISOString() });
    await db.updateProjectAdminNotes(projectId, JSON.stringify(notes));
    res.redirect(`/admin/projects/${encodeProjectId(projectId)}?message=Note+added`);
  } catch (e) {
    console.error('Add note error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}?error=Failed+to+add+note`);
  }
});

router.post('/admin/projects/:id/notes/:noteIndex/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const noteIndex = parseInt(req.params.noteIndex);
    const project = await db.getProject(projectId);
    let notes = [];
    try { notes = JSON.parse(project.admin_notes || '[]'); } catch(e) {}
    notes.splice(noteIndex, 1);
    await db.updateProjectAdminNotes(projectId, JSON.stringify(notes));
    res.redirect(`/admin/projects/${encodeProjectId(projectId)}?message=Note+deleted`);
  } catch (e) {
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}?error=Failed+to+delete+note`);
  }
});

// Unpublish design
router.post('/admin/projects/:id/design/unpublish', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const result = loadNewestDesign(req.params.id);
    if (!result) return res.status(404).send('No design found');
    const { design } = result;
    design.published = false;
    design.publishedAt = null;
    saveDesign(design);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/design?message=Design+unpublished`);
  } catch (e) {
    console.error('Unpublish error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/design?error=Unpublish+failed`);
  }
});

// Delete a design version
router.post('/admin/projects/:id/design/:designId/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const filePath = path.join(DESIGNS_DIR, req.params.designId + '.json');
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}?message=Design+deleted`);
  } catch (e) {
    console.error('Delete design error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}?error=Delete+failed`);
  }
});

// Accept assumption
router.post('/admin/projects/:id/design/accept-assumption', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { designId, questionText, assumption } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Design not found' });
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    design.acceptedAssumptions = design.acceptedAssumptions || [];
    design.acceptedAssumptions.push({ question: questionText, assumption, acceptedBy: req.user.email, ts: new Date().toISOString() });

    if (design.questions && Array.isArray(design.questions)) {
      design.questions = design.questions.filter(q => {
        const qt = (typeof q === 'object') ? q.text : String(q);
        return qt !== questionText;
      });
    }

    fs.writeFileSync(filePath, JSON.stringify(design, null, 2));
    res.json({ ok: true });
  } catch (e) {
    console.error('Accept assumption error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Assign question to customer
router.post('/admin/projects/:id/design/assign-question', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { designId, questionText, assignedTo } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Design not found' });
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (design.questions && Array.isArray(design.questions)) {
      design.questions = design.questions.map(q => {
        const qText = (typeof q === 'object') ? q.text : String(q);
        if (qText === questionText) {
          if (typeof q === 'object') { q.assignedTo = assignedTo || 'customer'; return q; }
          else return { text: qText, id: 0, assignedTo: assignedTo || 'customer' };
        }
        return q;
      });
    }
    fs.writeFileSync(filePath, JSON.stringify(design, null, 2));
    res.json({ success: true });
  } catch (e) {
    console.error('Assign question error:', e);
    res.status(500).json({ error: 'Failed to assign question' });
  }
});

// Customer: view published design
router.get('/customer/projects/:id/design', auth.authenticate, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).send('Project not found');
    if (req.user.role === 'customer' && project.user_id !== req.user.id) {
      const share = await db.getShareByProjectAndUser(projectId, req.user.id);
      if (!share) return res.status(403).send('Forbidden');
    }

    const result = loadNewestDesign(projectId);
    if (!result || !result.design.published) return res.status(404).send('No published design available');
    const { design } = result;

    res.render('customer/project-design', { user: req.user, projectId, project, design, title: project.name + ' - Design' });
  } catch (e) {
    console.error('Customer design view error:', e);
    res.status(500).send('Failed to load design');
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

// Customer: answer assigned question
router.post('/customer/projects/:id/design/answer', auth.authenticate, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (req.user.role === 'customer' && project.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

    const { designId, question, answer } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
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

// Poll generation status
router.get('/admin/projects/:id/generation-status', auth.authenticate, auth.requireAdmin, (req, res) => {
  const status = generationStatus[req.params.id];
  if (!status) return res.json({ status: 'idle' });
  res.json(status);
});

// Export helpers for other modules
module.exports = router;
module.exports.loadNewestDesign = loadNewestDesign;
module.exports.saveDesign = saveDesign;
module.exports.DESIGNS_DIR = DESIGNS_DIR;
