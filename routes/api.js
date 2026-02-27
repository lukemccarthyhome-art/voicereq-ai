const router = require('express').Router();
const express = require('express');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const db = require('../database-adapter');
const auth = require('../auth');
const { uploadsDir, DESIGNS_DIR } = require('../helpers/paths');
const { encodeProjectId, resolveProjectId } = require('../helpers/ids');
const { apiAuth, verifySessionOwnership, verifyFileOwnership } = require('../middleware/auth-middleware');
const { optionalAuth } = require('../middleware/auth-middleware');
const { upload, importUpload } = require('../middleware/uploads');
const { uploadLimiter } = require('../middleware/rate-limiters');

// Decode hashed IDs in :id route params
router.param('id', (req, res, next, val) => {
  req.params.id = resolveProjectId(val);
  next();
});

// File upload and text extraction endpoint
router.post('/api/upload', optionalAuth, uploadLimiter, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });

    let content = '';
    const ext = path.extname(file.originalname).toLowerCase();
    const filePath = file.path;

    // Extract text based on file type
    if (['.txt', '.md', '.csv', '.json', '.xml', '.yaml', '.yml', '.html', '.css', '.js', '.ts', '.py', '.java', '.rb'].includes(ext)) {
      content = fs.readFileSync(filePath, 'utf8');
    } else if (['.doc', '.docx'].includes(ext)) {
      try {
        const mammoth = require('mammoth');
        const result = await mammoth.extractRawText({ path: filePath });
        content = result.value;
      } catch (e) {
        console.log('mammoth not available, trying textract fallback');
        content = '[Word document: ' + file.originalname + ' — install mammoth for text extraction: npm install mammoth]';
      }
    } else if (ext === '.pdf') {
      try {
        const { PDFParse } = require('pdf-parse');
        const dataBuffer = new Uint8Array(fs.readFileSync(filePath));
        const parser = new PDFParse(dataBuffer);
        await parser.load();
        const result = await parser.getText();
        if (result && result.pages) {
          content = result.pages.map(p => p.text).join('\n\n');
        } else if (typeof result === 'string') {
          content = result;
        } else {
          content = JSON.stringify(result);
        }
        if (!content || content.trim().length === 0) {
          content = '[PDF: ' + file.originalname + ' — document appears to be image-based or empty. Text extraction returned no content.]';
        }
      } catch (e) {
        console.log('pdf-parse error:', e.message);
        content = '[PDF: ' + file.originalname + ' — text extraction failed: ' + e.message + ']';
      }
    } else if (['.xlsx', '.xls'].includes(ext)) {
      try {
        const XLSX = require('xlsx');
        const workbook = XLSX.readFile(filePath);
        const sheets = workbook.SheetNames.map(name => {
          const sheet = workbook.Sheets[name];
          return '## ' + name + '\n' + XLSX.utils.sheet_to_csv(sheet);
        });
        content = sheets.join('\n\n');
      } catch (e) {
        console.log('xlsx error:', e.message);
        content = '[Excel: ' + file.originalname + ' — install xlsx for extraction: npm install xlsx]';
      }
    } else if (['.pptx'].includes(ext)) {
      content = '[PowerPoint: ' + file.originalname + ' — uploaded successfully. Text extraction for .pptx is not yet supported.]';
    } else if (['.rtf'].includes(ext)) {
      try {
        content = fs.readFileSync(filePath, 'utf8').replace(/\\[a-z]+\d* ?/g, '').replace(/[{}]/g, '');
      } catch (e) {
        content = '[RTF: ' + file.originalname + ' — failed to extract text]';
      }
    } else if (['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg'].includes(ext)) {
      content = '[Image: ' + file.originalname + ' — uploaded successfully. Image content available for visual review.]';
    } else {
      content = '[File: ' + file.originalname + ' (' + ext + ') — uploaded successfully. Text extraction not available for this format.]';
    }

    // Keep the file — rename to original name
    const savedPath = path.join(uploadsDir, file.originalname);
    fs.renameSync(filePath, savedPath);

    const fullContentLength = content.length;

    // Truncate DB storage if very long (full file remains on disk)
    if (content.length > 8000) {
      content = content.substring(0, 8000) + '\n\n[...truncated, ' + content.length + ' total characters]';
    }

    // Save to database if project/session provided
    const { projectId, sessionId } = req.body;
    let fileId = null;
    let description = '';

    if (projectId) {
      // Verify ownership
      if (req.user.role !== 'admin') {
        const proj = await db.getProject(projectId);
        if (!proj || proj.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
      }
      const result = await db.createFile(
        projectId,
        sessionId || null,
        file.originalname,
        file.originalname,
        file.mimetype,
        file.size,
        content,
        null
      );
      fileId = result.lastInsertRowid;

      // Generate AI description for the document
      if (content && content.length > 50) {
        try {
          const OPENAI_KEY = process.env.OPENAI_API_KEY;
          if (OPENAI_KEY) {
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + OPENAI_KEY
              },
              body: JSON.stringify({
                model: process.env.LLM_MODEL || 'gpt-4.1',
                messages: [{
                  role: 'system',
                  content: 'Analyze this document and write a concise 2-3 sentence description that covers: (1) what type of document it is, (2) its key content/purpose, and (3) how it could be utilised in the project — e.g. informing requirements, defining constraints, identifying stakeholders, shaping business rules, etc. Be specific about what project-relevant information can be extracted from it.'
                }, {
                  role: 'user',
                  content: `Document: ${file.originalname}\n\nContent: ${content.substring(0, 2000)}${content.length > 2000 ? '...' : ''}`
                }]
              })
            });

            if (response.ok) {
              const data = await response.json();
              description = data.choices[0].message.content.trim();
              await db.updateFileDescription(fileId, description);
            }
          }
        } catch (e) {
          console.error('Failed to generate file description:', e);
        }
      }
    }

    console.log('📄 Processed file:', file.originalname, '— extracted', content.length, 'chars', description ? '— generated description' : '');

    res.json({
      filename: file.originalname,
      content: content,
      charCount: content.length,
      description: description,
      fileId: fileId
    });
  } catch (e) {
    console.error('File processing error:', e);
    res.status(500).json({ error: 'Failed to process file: ' + e.message });
  }
});

// Analyze file content and extract requirements using OpenAI
router.post('/api/analyze', optionalAuth, express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { filename, content } = req.body;
    const OPENAI_KEY = process.env.OPENAI_API_KEY;

    if (!OPENAI_KEY) {
      return res.status(500).json({ error: 'OpenAI API key not configured' });
    }

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OPENAI_KEY
      },
      body: JSON.stringify({
        model: process.env.LLM_MODEL || 'gpt-4.1',
        messages: [{
          role: 'system',
          content: `You are a business analyst extracting software requirements from a document. Analyze the document and extract any requirements, specifications, constraints, stakeholders, or project details.

Return a JSON object with this exact structure:
{
  "summary": "Brief 2-3 sentence summary of the document",
  "description": "Concise 1-2 sentence description of what type of document this is",
  "requirements": [
    {"category": "Project Overview|Stakeholders|Functional Requirements|Non-Functional Requirements|Constraints|Success Criteria", "text": "Clear requirement statement"}
  ]
}

Only include actual requirements, specifications, or important project facts. Do not include filler or obvious statements. Be specific and actionable. Return valid JSON only.`
        }, {
          role: 'user',
          content: 'Analyze this document called "' + filename + '":\n\n' + content
        }],
        response_format: { type: 'json_object' }
      })
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('OpenAI analyze error:', err);
      throw new Error('Analysis failed');
    }

    const data = await response.json();
    const analysis = JSON.parse(data.choices[0].message.content);
    console.log('📊 Analyzed', filename, '—', analysis.requirements?.length || 0, 'requirements found');

    res.json(analysis);
  } catch (e) {
    console.error('Analysis error:', e);
    res.status(500).json({ error: 'Analysis failed: ' + e.message });
  }
});

// Update file description
router.put('/api/files/:id/description', apiAuth, express.json(), verifyFileOwnership, async (req, res) => {
  try {
    const { description } = req.body;
    const fileId = req.params.id;
    await db.updateFileDescription(fileId, description);
    res.json({ success: true });
  } catch (e) {
    console.error('Update file description error:', e);
    res.status(500).json({ error: 'Failed to update file description' });
  }
});

// Analyze full session
router.post('/api/analyze-session', optionalAuth, express.json({ limit: '20mb' }), async (req, res) => {
  try {
    const { transcript, fileContents, sessionId: rawSessionId, projectId: rawProjectId, existingRequirements } = req.body;
    const projectId = resolveProjectId(rawProjectId);
    const sessionId = resolveProjectId(rawSessionId);

    // Verify ownership
    if (projectId && req.user.role !== 'admin') {
      const proj = await db.getProject(projectId);
      if (!proj || proj.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    }

    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (!OPENAI_KEY) {
      return res.status(500).json({ error: 'OpenAI API key not configured' });
    }

    // Build comprehensive context
    let analysisContent = '';

    if (transcript && transcript.length > 0) {
      analysisContent += '## CONVERSATION TRANSCRIPT\n\n';
      transcript.forEach(msg => {
        const speaker = msg.role === 'ai' ? 'Business Analyst' : 'Client';
        analysisContent += `**${speaker}:** ${msg.text}\n\n`;
      });
    }

    let filesToAnalyze = fileContents;

    // Load files from DB for descriptions and metadata
    let dbFiles = [];
    if (sessionId) {
      dbFiles = await db.getFilesBySession(sessionId) || [];
    }
    if ((!dbFiles || dbFiles.length === 0) && projectId) {
      dbFiles = await db.getFilesByProject(projectId) || [];
    }

    // Read FULL file content from disk (not truncated DB text)
    if ((!fileContents || Object.keys(fileContents).length === 0) && dbFiles.length > 0) {
      filesToAnalyze = {};
      for (const file of dbFiles) {
        const fname = file.original_name || file.filename;
        const diskPath = path.join(uploadsDir, fname);

        if (fs.existsSync(diskPath)) {
          try {
            const ext = path.extname(fname).toLowerCase();
            let fullContent = '';
            if (['.txt', '.md', '.csv', '.json', '.xml', '.yaml', '.yml', '.html', '.css', '.js', '.ts', '.py'].includes(ext)) {
              fullContent = fs.readFileSync(diskPath, 'utf8');
            } else if (['.doc', '.docx'].includes(ext)) {
              try { const mammoth = require('mammoth'); const r = await mammoth.extractRawText({ path: diskPath }); fullContent = r.value; } catch(e) { fullContent = file.extracted_text || ''; }
            } else if (ext === '.pdf') {
              try { const { PDFParse } = require('pdf-parse'); const buf = new Uint8Array(fs.readFileSync(diskPath)); const parser = new PDFParse(buf); await parser.load(); const r = await parser.getText(); fullContent = r && r.pages ? r.pages.map(p => p.text).join('\n\n') : (typeof r === 'string' ? r : ''); } catch(e) { fullContent = file.extracted_text || ''; }
            } else {
              fullContent = file.extracted_text || '';
            }
            if (fullContent) {
              if (fullContent.length > 50000) {
                filesToAnalyze[fname] = fullContent.substring(0, 50000) + '\n\n[...truncated from ' + fullContent.length + ' chars — first 50,000 included]';
              } else {
                filesToAnalyze[fname] = fullContent;
              }
            }
          } catch(e) {
            if (file.extracted_text) filesToAnalyze[fname] = file.extracted_text;
          }
        } else if (file.extracted_text) {
          filesToAnalyze[fname] = file.extracted_text;
        }
      }
    }

    if (filesToAnalyze && Object.keys(filesToAnalyze).length > 0) {
      analysisContent += '## UPLOADED DOCUMENTS\n\n';
      for (const [filename, content] of Object.entries(filesToAnalyze)) {
        const dbFile = dbFiles.find(f => f.original_name === filename);
        if (dbFile && dbFile.description) {
          analysisContent += `### ${filename}\n**Document Context:** ${dbFile.description}\n\n${content}\n\n---\n\n`;
        } else {
          analysisContent += `### ${filename}\n\n${content}\n\n---\n\n`;
        }
      }
    }

    if (existingRequirements && Object.keys(existingRequirements).length > 0) {
      analysisContent += '## ALREADY CAPTURED REQUIREMENTS (DO NOT REPEAT THESE)\n\n';
      for (const [cat, items] of Object.entries(existingRequirements)) {
        if (Array.isArray(items) && items.length > 0) {
          analysisContent += `### ${cat}\n`;
          items.forEach(r => { analysisContent += `- ${r}\n`; });
          analysisContent += '\n';
        }
      }
    }

    if (!analysisContent.trim()) {
      return res.status(400).json({ error: 'No content to analyze' });
    }

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OPENAI_KEY
      },
      body: JSON.stringify({
        model: process.env.LLM_MODEL || 'gpt-4.1',
        max_completion_tokens: 4096,
        messages: [{
          role: 'system',
          content: `You are an expert business analyst conducting detailed requirements analysis. Analyze the provided conversation transcript and uploaded documents to extract NEW requirements not already captured.

CRITICAL: A section titled "ALREADY CAPTURED REQUIREMENTS" lists requirements that have already been identified. DO NOT repeat or rephrase any of these. ONLY return genuinely NEW requirements, additional details, or refinements discovered in the latest conversation or documents. If nothing new is found for a category, omit that category entirely.

DETAIL PRESERVATION IS ESSENTIAL:
- The user has taken time to explain specifics — capture ALL relevant detail, not just summaries
- If the user mentions specific numbers, names, platforms, tools, frequencies, workflows, or examples — include them
- Do NOT simplify "I need to contact 200 people across 3 platforms weekly" into "System should support multi-platform communication"
- Preserve the WHY behind requirements, not just the WHAT
- Each requirement should be a rich, self-contained statement that someone unfamiliar with the conversation could understand
- When the user provides context, reasoning, or constraints around a requirement, fold that into the requirement statement
- Longer, detailed requirement statements are BETTER than short generic ones

Return a JSON object with this exact structure:
{
  "requirements": {
    "Project Overview": ["Detailed statements about project purpose, scope, objectives, and context"],
    "Stakeholders": ["Specific user roles, personas, or stakeholder groups with their needs and context"],
    "Functional Requirements": ["Detailed feature descriptions including specific behaviors, workflows, edge cases, and examples the user mentioned"],
    "Non-Functional Requirements": ["Performance targets, security needs, usability expectations, scalability requirements — with specific numbers/thresholds where given"],
    "Constraints": ["Budget, timeline, technology, regulatory, or resource limitations with specifics"],
    "Success Criteria": ["Measurable goals, KPIs, or definition of done with concrete targets"],
    "Business Rules": ["Policies, regulations, or business logic — include the reasoning/context behind each rule"],
    "User Workflows": ["Step-by-step processes the user described, including current pain points and desired improvements"],
    "Integrations": ["Specific platforms, tools, APIs, or systems mentioned and how they should connect"],
    "Data & Content": ["What data is involved, its sources, formats, volumes, and how it should be managed"],
    "Cost & Value": ["Current cost of existing process, expected value/ROI, human labour equivalent cost, cost savings potential, business case justification"]
  },
  "summary": "3-5 sentence detailed summary covering the project's purpose, key challenges, and primary goals",
  "keyInsights": ["Important insights, themes, or non-obvious implications from the analysis"],
  "documentReferences": ["Quotes or key points from uploaded documents that support requirements"]
}

Guidelines:
- PRESERVE SPECIFICITY: include exact numbers, names, tools, platforms, frequencies, and examples from the conversation
- Write requirements at the detail level the user provided — do not abstract away their specifics
- If the user said something important, it should be recognizable in the output
- Group related requirements logically but don't merge distinct requirements into one
- Include context from both conversation and documents
- Only include categories that have actual requirements
- A single detailed requirement is worth more than five vague ones

Return valid JSON only.`
        }, {
          role: 'user',
          content: analysisContent
        }],
        response_format: { type: 'json_object' }
      })
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('OpenAI session analysis error:', err);
      throw new Error('Session analysis failed: ' + err.substring(0, 200));
    }

    const data = await response.json();
    const respContent = data.choices[0].message.content;
    if (!respContent) {
      console.error('OpenAI returned empty content. Usage:', JSON.stringify(data.usage));
      throw new Error('Model returned empty content — try a different model');
    }
    const analysis = JSON.parse(respContent);

    const totalReqs = Object.values(analysis.requirements || {}).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0);

    console.log('🎯 Session analyzed:', {
      sessionId,
      projectId,
      transcriptMessages: transcript?.length || 0,
      filesAnalyzed: Object.keys(fileContents || {}).length,
      requirementsExtracted: totalReqs,
      categories: Object.keys(analysis.requirements || {}).length
    });

    res.json(analysis);
  } catch (e) {
    console.error('Session analysis error:', e);
    res.status(500).json({ error: 'Session analysis failed: ' + e.message });
  }
});

// Text chat API
router.post('/api/chat', optionalAuth, express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { message, transcript, fileContents, sessionId } = req.body;
    const OPENAI_KEY = process.env.OPENAI_API_KEY;

    if (!OPENAI_KEY) {
      return res.status(500).json({ error: 'OpenAI API key not configured' });
    }

    let contextContent = '';

    if (fileContents && Object.keys(fileContents).length > 0) {
      contextContent += '\n\n=== UPLOADED DOCUMENTS ===\n';
      Object.entries(fileContents).forEach(([filename, content]) => {
        contextContent += `\n--- ${filename} ---\n${content}\n`;
      });
    }

    if (transcript && Array.isArray(transcript) && transcript.length > 0) {
      contextContent += '\n\n=== CONVERSATION HISTORY ===\n';
      transcript.forEach(msg => {
        if (msg.role && msg.text) {
          contextContent += `${msg.role.toUpperCase()}: ${msg.text}\n`;
        }
      });
    }

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OPENAI_KEY
      },
      body: JSON.stringify({
        model: process.env.LLM_MODEL || 'gpt-4.1',
        messages: [{
          role: 'system',
          content: `You are an expert business analyst helping with requirements gathering and project analysis. You have access to uploaded documents and conversation history for context.

          Your role:
          - Help clarify and refine business requirements
          - Ask insightful follow-up questions
          - Identify gaps or inconsistencies in requirements
          - Suggest best practices and considerations
          - Be conversational but professional

          CONVERSATION STYLE:
          - Do NOT recap the full conversation each time. Focus on what was JUST discussed.
          - When summarising understanding, only cover the most recent points or new information.
          - Reference earlier topics briefly ("building on what you said about X...") rather than restating them.

          COST & VALUE DISCOVERY (important — approach gently once core requirements are mostly understood):
          - Once the client has explained the core of what they need, naturally explore the business value:
          - If it replaces an existing process: "How is this handled today? What does that currently cost in time or money?"
          - For new initiatives: "What value do you see this bringing to the organisation?" and "If you were to do this manually with people, roughly what would that look like cost-wise?"
          - Frame these as helping understand priorities, not as an interrogation about budget.
          - The goal is to establish whether the project delivers clear ROI — this helps everyone make good decisions.
          - Don't ask all cost questions at once. Weave them in naturally over 2-3 exchanges.

          TECHNICAL READINESS DISCOVERY (after core business requirements are mostly captured):
          - Once you understand WHAT they need, gently explore HOW their current tech landscape connects:
          - Existing tools/services: "What tools do you currently use for this? CRM, spreadsheets, email platform, project management?"
          - API access: "Do you have API access or login credentials for those services already?"
          - Data sources: "Where does the data live today? What format is it in — spreadsheets, database, manual records?"
          - Trigger frequency: "How often does this need to run — real-time, daily, weekly, or triggered by specific events?"
          - Third-party budget: "Are there any paid services or subscriptions you'd be open to using, or do we need to keep it free/low-cost?"
          - Technical comfort: "Who would be managing this day-to-day — do you have a dev team, an IT person, or would it just be you?"
          - Do NOT lead with these questions. Only ask after the core business problem and workflows are clear.
          - Weave these in naturally over 2-3 exchanges, don't dump them all at once.

          Context available:${contextContent}`
        }, {
          role: 'user',
          content: message
        }]
      })
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('OpenAI chat error:', err);
      throw new Error('Chat request failed');
    }

    const data = await response.json();
    const aiResponse = data.choices[0].message.content;

    console.log('💬 Chat response generated', {
      sessionId,
      messageLength: message.length,
      responseLength: aiResponse.length,
      contextLength: contextContent.length
    });

    res.json({ response: aiResponse });
  } catch (e) {
    console.error('Chat error:', e);
    res.status(500).json({ error: 'Chat failed: ' + e.message });
  }
});

// Project info API
router.get('/api/projects/:id', apiAuth, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Not found' });
    if (req.user.role !== 'admin' && project.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json({ id: project.id, name: project.name, description: project.description || '', status: project.status });
  } catch(e) {
    res.status(500).json({ error: 'Failed to get project' });
  }
});

// Session management API
router.get('/api/sessions/:id', apiAuth, verifySessionOwnership, async (req, res) => {
  try {
    const session = await db.getSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    const files = await db.getFilesBySession(req.params.id);
    session.files = files;
    res.json(session);
  } catch (e) {
    console.error('Get session error:', e);
    res.status(500).json({ error: 'Failed to get session' });
  }
});

router.put('/api/sessions/:id', apiAuth, express.json({ limit: '10mb' }), verifySessionOwnership, async (req, res) => {
  try {
    const { transcript, requirements, context, status } = req.body;
    await db.updateSession(req.params.id, transcript, requirements, context, status || 'active');
    res.json({ success: true });
  } catch (e) {
    console.error('Update session error:', e);
    res.status(500).json({ error: 'Failed to update session' });
  }
});

// POST /save endpoint for sendBeacon (page unload)
router.post('/api/sessions/:id/save', apiAuth, express.json({ limit: '10mb' }), verifySessionOwnership, async (req, res) => {
  try {
    const { transcript, requirements, context, status } = req.body;
    await db.updateSession(req.params.id, transcript, requirements, context, status || 'paused');
    console.log(`💾 Beacon save for session ${req.params.id} — ${(transcript || []).length} messages`);
    res.json({ success: true });
  } catch (e) {
    console.error('Beacon save error:', e);
    res.status(500).json({ error: 'Failed to save session' });
  }
});

// Download all assets + requirements as zip
router.post('/api/export-zip', apiAuth, express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { requirementsDoc } = req.body;

    res.set({
      'Content-Type': 'application/zip',
      'Content-Disposition': 'attachment; filename=voicereq-export-' + new Date().toISOString().split('T')[0] + '.zip'
    });

    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);

    if (requirementsDoc) {
      archive.append(requirementsDoc, { name: 'requirements.md' });
    }

    if (fs.existsSync(uploadsDir)) {
      const files = fs.readdirSync(uploadsDir);
      for (const file of files) {
        const filePath = path.join(uploadsDir, file);
        if (fs.statSync(filePath).isFile()) {
          archive.file(filePath, { name: 'assets/' + file });
        }
      }
    }

    await archive.finalize();
  } catch (e) {
    console.error('Zip export error:', e);
    res.status(500).json({ error: 'Export failed: ' + e.message });
  }
});

// Import project from ZIP
router.post('/admin/import-project', auth.authenticate, auth.requireAdmin, importUpload.single('zipfile'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send('No file uploaded');

    const zip = new AdmZip(req.file.buffer);
    const entries = zip.getEntries();

    let requirementsDoc = '';
    let projectName = 'Imported Project';
    let projectDescription = '';
    const assetFiles = [];

    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const name = entry.entryName;

      if (name === 'requirements.md' || name.endsWith('/requirements.md')) {
        requirementsDoc = entry.getData().toString('utf8');
        const nameMatch = requirementsDoc.match(/^#\s+(.+?)(?:\s*-\s*Requirements|\s*$)/m);
        if (nameMatch) projectName = nameMatch[1].trim();
        const companyMatch = requirementsDoc.match(/\*\*Company:\*\*\s*(.+)/);
        if (companyMatch) projectDescription = companyMatch[1].trim();
      } else if (name.startsWith('assets/') || name.startsWith('files/')) {
        assetFiles.push({ name: path.basename(name), data: entry.getData(), size: entry.header.size });
      }
    }

    if (req.body.projectName) projectName = req.body.projectName;
    if (req.body.projectDescription) projectDescription = req.body.projectDescription;

    const adminUser = req.user || { id: 1 };

    if (!projectDescription && requirementsDoc) {
      const companyMatch = requirementsDoc.match(/\*\*Company:\*\*\s*(.+)/);
      const firstPara = requirementsDoc.split('\n\n').find(p => p && !p.startsWith('#') && !p.startsWith('*') && !p.startsWith('-'));
      projectDescription = companyMatch ? companyMatch[1].trim() : (firstPara ? firstPara.trim().substring(0, 200) : 'Imported from ZIP');
    }

    const result = await db.createProject(adminUser.id, projectName, projectDescription || 'Imported from ZIP');
    const projectId = result.lastInsertRowid || result.id;

    if (requirementsDoc) {
      const requirements = {};
      const sectionRegex = /###\s+(.+)\n([\s\S]*?)(?=###|## |$)/g;
      let match;
      while ((match = sectionRegex.exec(requirementsDoc)) !== null) {
        const section = match[1].trim();
        const items = match[2].split('\n').filter(l => l.startsWith('- ')).map(l => l.replace(/^- /, '').trim());
        if (items.length > 0) requirements[section] = items;
      }

      let transcript = [];
      const transcriptSection = requirementsDoc.match(/## Full (?:Conversation History|Transcript)\n\n([\s\S]*?)(?=---|$)/);
      if (transcriptSection) {
        const msgRegex = /\*\*(\w+):\*\*\s*([\s\S]*?)(?=\*\*\w+:\*\*|$)/g;
        let m;
        while ((m = msgRegex.exec(transcriptSection[1])) !== null) {
          transcript.push({ role: m[1].toLowerCase() === 'ai' ? 'ai' : 'user', text: m[2].trim() });
        }
      }

      db.appendSessionMessageSafe(projectId, JSON.stringify({
        role: 'system',
        text: 'Imported from project ZIP',
        timestamp: new Date().toISOString()
      }));

      const sessions = await db.getSessionsByProject(projectId);
      if (sessions.length > 0) {
        const sid = sessions[0].id;
        await db.updateSession(sid, transcript, requirements, {}, 'completed');
      }
    }

    if (assetFiles.length > 0) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      const sessions = await db.getSessionsByProject(projectId);
      const sessionId = sessions.length > 0 ? sessions[0].id : null;

      for (const asset of assetFiles) {
        const filename = Date.now() + '-' + asset.name;
        const filePath = path.join(uploadsDir, filename);
        fs.writeFileSync(filePath, asset.data);
        db.createFile(projectId, sessionId, filename, asset.name, '', asset.size, '', '');
      }
    }

    console.log(`📦 Imported project "${projectName}" (ID: ${projectId}) with ${assetFiles.length} assets`);
    res.redirect('/admin/projects/' + encodeProjectId(projectId));
  } catch (e) {
    console.error('Import error:', e);
    res.status(500).send('Import failed: ' + e.message);
  }
});

// Import ZIP into existing project
router.post('/admin/projects/:id/import', auth.authenticate, auth.requireAdmin, importUpload.single('zipfile'), async (req, res) => {
  const projectId = req.params.id;
  try {
    if (!req.file) return res.status(400).send('No file uploaded');

    const project = await db.getProject(projectId);
    if (!project) return res.status(404).send('Project not found');

    const zip = new AdmZip(req.file.buffer);
    const entries = zip.getEntries();

    let requirementsDoc = '';
    const assetFiles = [];

    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const name = entry.entryName;
      if (name === 'requirements.md' || name.endsWith('/requirements.md')) {
        requirementsDoc = entry.getData().toString('utf8');
      } else if (name.startsWith('assets/') || name.startsWith('files/')) {
        assetFiles.push({ name: path.basename(name), data: entry.getData(), size: entry.header.size });
      }
    }

    if (requirementsDoc) {
      requirementsDoc = requirementsDoc.replace(/\\n/g, '\n');

      const requirements = {};
      const reqSection = requirementsDoc.match(/## Requirements\n\n([\s\S]*?)(?=\n## Full|\n## Project Assets|$)/);
      if (reqSection) {
        const sectionRegex = /### (.+)\n\n([\s\S]*?)(?=\n### |$)/g;
        let match;
        while ((match = sectionRegex.exec(reqSection[1])) !== null) {
          const items = match[2].split('\n').filter(l => l.startsWith('- ')).map(l => l.replace(/^- /, '').trim());
          if (items.length > 0) requirements[match[1].trim()] = items;
        }
      }

      const transcript = [];
      const tSection = requirementsDoc.match(/## Full (?:Conversation History|Transcript)\n\n([\s\S]*?)(?=\n---|$)/);
      if (tSection) {
        const msgRegex = /\*\*(\w+):\*\*\s*([\s\S]*?)(?=\n\n\*\*\w+:\*\*|$)/g;
        let m;
        while ((m = msgRegex.exec(tSection[1])) !== null) {
          transcript.push({ role: m[1].toLowerCase() === 'ai' ? 'ai' : 'user', text: m[2].trim() });
        }
      }

      let sessions = await db.getSessionsByProject(projectId);
      if (sessions.length === 0) {
        await db.appendSessionMessageSafe(projectId, JSON.stringify({ role: 'system', text: 'Imported from ZIP', timestamp: new Date().toISOString() }));
        sessions = await db.getSessionsByProject(projectId);
      }

      if (sessions.length > 0) {
        await db.updateSession(sessions[0].id, transcript, requirements, {}, 'paused');
      }

      console.log(`📥 Imported into project "${project.name}" (ID: ${projectId}): ${transcript.length} messages, ${Object.keys(requirements).length} requirement categories`);
    }

    if (assetFiles.length > 0) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      const sessions = await db.getSessionsByProject(projectId);
      const sessionId = sessions.length > 0 ? sessions[0].id : null;
      for (const asset of assetFiles) {
        const filename = Date.now() + '-' + asset.name;
        const filePath = path.join(uploadsDir, filename);
        fs.writeFileSync(filePath, asset.data);
        db.createFile(projectId, sessionId, filename, asset.name, '', asset.size, '', '');
      }
    }

    res.redirect('/admin/projects/' + encodeProjectId(projectId));
  } catch (e) {
    console.error('Project import error:', e);
    res.status(500).send('Import failed: ' + e.message);
  }
});

router.get('/api/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Crash log endpoint
router.get('/api/crash-log', (req, res) => {
  const key = req.headers['x-backup-key'];
  if (!key || key !== (process.env.BACKUP_KEY || 'morti-backup-2026')) {
    return res.status(403).json({ error: 'Invalid key' });
  }
  const logPath = process.env.DATA_DIR ? path.join(process.env.DATA_DIR, 'crash.log') : null;
  if (!logPath || !fs.existsSync(logPath)) return res.json({ log: 'No crash log found' });
  const content = fs.readFileSync(logPath, 'utf8');
  res.type('text/plain').send(content.slice(-5000));
});

// Protected backup endpoint
router.get('/api/backup', async (req, res) => {
  const backupKey = req.headers['x-backup-key'];
  if (!backupKey || backupKey !== (process.env.BACKUP_KEY || 'morti-backup-2026')) {
    return res.status(403).json({ error: 'Invalid backup key' });
  }
  try {
    const users = await db.getAllUsers();
    const projects = await db.getAllProjects();
    const allSessions = [];
    const allFiles = [];
    for (const p of projects) {
      const sessions = await db.getSessionsByProject(p.id);
      sessions.forEach(s => allSessions.push(s));
      const files = await db.getFilesByProject(p.id);
      files.forEach(f => allFiles.push(f));
    }
    const designs = [];
    try {
      if (fs.existsSync(DESIGNS_DIR)) {
        fs.readdirSync(DESIGNS_DIR).forEach(f => {
          try {
            designs.push(JSON.parse(fs.readFileSync(path.join(DESIGNS_DIR, f), 'utf8')));
          } catch(e) {}
        });
      }
    } catch(e) {}
    res.json({
      timestamp: new Date().toISOString(),
      users: users.map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role, company: u.company, created_at: u.created_at })),
      projects,
      sessions: allSessions,
      files: allFiles.map(f => ({ id: f.id, project_id: f.project_id, session_id: f.session_id, filename: f.filename, original_name: f.original_name, description: f.description, size: f.size, created_at: f.created_at })),
      designs,
      stats: { users: users.length, projects: projects.length, sessions: allSessions.length, files: allFiles.length, designs: designs.length }
    });
  } catch (e) {
    console.error('Backup error:', e);
    res.status(500).json({ error: 'Backup failed: ' + e.message });
  }
});

module.exports = router;
