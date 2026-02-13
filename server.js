const express = require('express');
const path = require('path');
const fs = require('fs');
const https = require('https');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const archiver = require('archiver');

require('dotenv').config();

// Import database and authentication
const db = require('./database');
const auth = require('./auth');

const app = express();
const PORT = 3000;
const HTTPS_PORT = 3443;

// Middleware
app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// File upload setup
const upload = multer({ 
  dest: path.join(__dirname, 'uploads/'),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Ensure directories exist
fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });

// Serve static files with no-cache
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  setHeaders: (res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  }
}));

// === AUTHENTICATION ROUTES ===

app.get('/login', (req, res) => {
  if (req.cookies.authToken) {
    try {
      auth.authenticate(req, res, () => {
        return res.redirect(req.user.role === 'admin' ? '/admin' : '/dashboard');
      });
      return;
    } catch {}
  }
  res.render('login', { error: null, email: '' });
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.getUser(email);
    
    if (!user || !auth.verifyPassword(password, user.password_hash)) {
      return res.render('login', { error: 'Invalid email or password', email });
    }
    
    const token = auth.generateToken(user);
    res.cookie('authToken', token, { 
      httpOnly: true, 
      secure: false, // Set to true in production with HTTPS
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
  } catch (e) {
    console.error('Login error:', e);
    res.render('login', { error: 'Login failed', email: req.body.email || '' });
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('authToken');
  res.redirect('/login');
});

// === ADMIN ROUTES ===

app.get('/admin', auth.authenticate, auth.requireAdmin, (req, res) => {
  const stats = db.getStats();
  const recentCustomers = db.getAllUsers().slice(0, 8);
  const recentProjects = db.getAllProjects().slice(0, 8);
  
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

app.get('/admin/customers', auth.authenticate, auth.requireAdmin, (req, res) => {
  const customers = db.getAllUsers();
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

app.post('/admin/customers', auth.authenticate, auth.requireAdmin, (req, res) => {
  try {
    const { name, email, company, password } = req.body;
    const finalPassword = password || Math.random().toString(36).slice(-8);
    
    db.createUser(email, name, company, 'customer', finalPassword);
    res.redirect('/admin/customers?message=Customer created successfully');
  } catch (e) {
    console.error('Create customer error:', e);
    res.redirect('/admin/customers?error=Failed to create customer');
  }
});

app.post('/admin/customers/:id', auth.authenticate, auth.requireAdmin, (req, res) => {
  try {
    const { name, email, company } = req.body;
    db.updateUser(req.params.id, email, name, company);
    res.redirect('/admin/customers?message=Customer updated successfully');
  } catch (e) {
    console.error('Update customer error:', e);
    res.redirect('/admin/customers?error=Failed to update customer');
  }
});

app.post('/admin/customers/:id/delete', auth.authenticate, auth.requireAdmin, (req, res) => {
  try {
    db.deleteUser(req.params.id);
    res.redirect('/admin/customers?message=Customer deleted successfully');
  } catch (e) {
    console.error('Delete customer error:', e);
    res.redirect('/admin/customers?error=Failed to delete customer');
  }
});

app.get('/admin/projects', auth.authenticate, auth.requireAdmin, (req, res) => {
  const projects = db.getAllProjects();
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

app.get('/admin/projects/:id', auth.authenticate, auth.requireAdmin, (req, res) => {
  const project = db.getProject(req.params.id);
  if (!project) {
    return res.status(404).send('Project not found');
  }
  
  const sessions = db.getSessionsByProject(req.params.id);
  const files = db.getFilesByProject(req.params.id);
  
  res.render('admin/project-detail', {
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

// === CUSTOMER ROUTES ===

app.get('/dashboard', auth.authenticate, auth.requireCustomer, (req, res) => {
  const projects = db.getProjectsByUser(req.user.id);
  res.render('customer/dashboard', {
    user: req.user,
    projects,
    title: 'Dashboard',
    currentPage: 'customer-dashboard',
    breadcrumbs: [{ name: 'Dashboard' }]
  });
});

app.get('/projects', auth.authenticate, auth.requireCustomer, (req, res) => {
  const projects = db.getProjectsByUser(req.user.id);
  const isNewProject = req.query.new === 'true';
  
  res.render('customer/projects', {
    user: req.user,
    projects,
    isNewProject,
    title: 'My Projects',
    currentPage: 'customer-projects',
    breadcrumbs: [
      { name: 'Dashboard', url: '/dashboard' },
      { name: 'Projects' }
    ]
  });
});

app.get('/projects/new', auth.authenticate, auth.requireCustomer, (req, res) => {
  res.redirect('/projects?new=true');
});

app.post('/projects', auth.authenticate, auth.requireCustomer, (req, res) => {
  try {
    const { name, description } = req.body;
    const result = db.createProject(req.user.id, name, description);
    res.redirect(`/projects/${result.lastInsertRowid}?message=Project created successfully`);
  } catch (e) {
    console.error('Create project error:', e);
    res.redirect('/projects?error=Failed to create project');
  }
});

app.get('/projects/:id', auth.authenticate, auth.requireCustomer, (req, res) => {
  const project = db.getProject(req.params.id);
  if (!project || project.user_id !== req.user.id) {
    return res.status(404).send('Project not found');
  }
  
  const sessions = db.getSessionsByProject(req.params.id);
  const files = db.getFilesByProject(req.params.id);
  const activeSession = db.getLatestSessionForProject(req.params.id);
  
  res.render('customer/project', {
    user: req.user,
    project,
    sessions,
    files,
    activeSession,
    title: project.name,
    currentPage: 'customer-projects',
    breadcrumbs: [
      { name: 'Dashboard', url: '/dashboard' },
      { name: 'Projects', url: '/projects' },
      { name: project.name }
    ]
  });
});

app.get('/projects/:id/session', auth.authenticate, auth.requireCustomer, (req, res) => {
  const project = db.getProject(req.params.id);
  if (!project || project.user_id !== req.user.id) {
    return res.status(404).send('Project not found');
  }
  
  // Check for existing active session
  let activeSession = db.getLatestSessionForProject(req.params.id);
  if (!activeSession || activeSession.status === 'completed') {
    // Create new session
    const result = db.createSession(req.params.id);
    activeSession = { id: result.lastInsertRowid };
  }
  
  res.redirect(`/voice-session?project=${req.params.id}&session=${activeSession.id}`);
});

app.get('/voice-session', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// === API ROUTES ===

// File upload and text extraction endpoint
app.post('/api/upload', upload.single('file'), async (req, res) => {
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
        const pdfParse = require('pdf-parse');
        const dataBuffer = fs.readFileSync(filePath);
        const data = await pdfParse(dataBuffer);
        content = data.text;
      } catch (e) {
        console.log('pdf-parse not available');
        content = '[PDF: ' + file.originalname + ' — install pdf-parse for extraction: npm install pdf-parse]';
      }
    } else {
      content = '[File: ' + file.originalname + ' (' + ext + ') — unsupported format for text extraction]';
    }

    // Keep the file — rename to original name
    const savedPath = path.join(__dirname, 'uploads', file.originalname);
    fs.renameSync(filePath, savedPath);

    // Truncate if very long
    if (content.length > 8000) {
      content = content.substring(0, 8000) + '\n\n[...truncated, ' + content.length + ' total characters]';
    }

    // Save to database if project/session provided
    const { projectId, sessionId } = req.body;
    if (projectId) {
      db.createFile(
        projectId,
        sessionId || null,
        file.originalname,
        file.originalname,
        file.mimetype,
        file.size,
        content,
        null
      );
    }

    console.log('📄 Processed file:', file.originalname, '— extracted', content.length, 'chars');
    
    res.json({ 
      filename: file.originalname,
      content: content,
      charCount: content.length
    });
  } catch (e) {
    console.error('File processing error:', e);
    res.status(500).json({ error: 'Failed to process file: ' + e.message });
  }
});

// Analyze file content and extract requirements using OpenAI
app.post('/api/analyze', express.json({ limit: '10mb' }), async (req, res) => {
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
        model: 'gpt-3.5-turbo',
        temperature: 0.3,
        messages: [{
          role: 'system',
          content: `You are a business analyst extracting software requirements from a document. Analyze the document and extract any requirements, specifications, constraints, stakeholders, or project details.

Return a JSON object with this exact structure:
{
  "summary": "Brief 2-3 sentence summary of the document",
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

// Analyze full session (conversation + files) for comprehensive requirements extraction
app.post('/api/analyze-session', express.json({ limit: '20mb' }), async (req, res) => {
  try {
    const { transcript, fileContents, sessionId, projectId } = req.body;
    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    
    if (!OPENAI_KEY) {
      return res.status(500).json({ error: 'OpenAI API key not configured' });
    }

    // Build comprehensive context
    let analysisContent = '';
    
    // Add conversation transcript
    if (transcript && transcript.length > 0) {
      analysisContent += '## CONVERSATION TRANSCRIPT\n\n';
      transcript.forEach(msg => {
        const speaker = msg.role === 'ai' ? 'Business Analyst' : 'Client';
        analysisContent += `**${speaker}:** ${msg.text}\n\n`;
      });
    }
    
    // Add uploaded files content
    if (fileContents && Object.keys(fileContents).length > 0) {
      analysisContent += '## UPLOADED DOCUMENTS\n\n';
      for (const [filename, content] of Object.entries(fileContents)) {
        analysisContent += `### ${filename}\n\n${content}\n\n---\n\n`;
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
        model: 'gpt-3.5-turbo',
        temperature: 0.3,
        max_tokens: 4000,
        messages: [{
          role: 'system',
          content: `You are an expert business analyst conducting requirements analysis. Analyze the provided conversation transcript and uploaded documents to extract comprehensive, structured requirements.

IMPORTANT: Focus on extracting clear, actionable requirements - not just restating what was said. Convert conversational statements into formal requirements.

Return a JSON object with this exact structure:
{
  "requirements": {
    "Project Overview": ["Clear statement about project purpose, scope, or objectives"],
    "Stakeholders": ["Specific user roles, personas, or stakeholder groups with their needs"],
    "Functional Requirements": ["What the system must do - specific features, capabilities, processes"],
    "Non-Functional Requirements": ["Performance, security, usability, scalability, compliance requirements"],
    "Constraints": ["Budget, timeline, technology, regulatory, or resource limitations"],
    "Success Criteria": ["Measurable goals, KPIs, or definition of done"],
    "Business Rules": ["Policies, regulations, or business logic that must be enforced"]
  },
  "summary": "2-3 sentence executive summary of the overall requirements",
  "keyInsights": ["Important insights or themes that emerged from the analysis"],
  "documentReferences": ["Quotes or key points from uploaded documents that support requirements"]
}

Guidelines:
- Convert conversational language to formal requirement statements
- Be specific and measurable where possible
- Group related requirements logically
- Include context from both conversation and documents
- Only include categories that have actual requirements
- Make each requirement statement clear and actionable
- Reference document content when it supports requirements

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
      throw new Error('Session analysis failed');
    }

    const data = await response.json();
    const analysis = JSON.parse(data.choices[0].message.content);
    
    // Count total requirements
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

// Session management API
app.get('/api/sessions/:id', (req, res) => {
  try {
    const session = db.getSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    res.json(session);
  } catch (e) {
    console.error('Get session error:', e);
    res.status(500).json({ error: 'Failed to get session' });
  }
});

app.put('/api/sessions/:id', express.json({ limit: '10mb' }), (req, res) => {
  try {
    const { transcript, requirements, context, status } = req.body;
    db.updateSession(req.params.id, transcript, requirements, context, status || 'active');
    res.json({ success: true });
  } catch (e) {
    console.error('Update session error:', e);
    res.status(500).json({ error: 'Failed to update session' });
  }
});

// Download all assets + requirements as zip
app.post('/api/export-zip', express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { requirementsDoc } = req.body;
    
    res.set({
      'Content-Type': 'application/zip',
      'Content-Disposition': 'attachment; filename=voicereq-export-' + new Date().toISOString().split('T')[0] + '.zip'
    });

    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);

    // Add requirements document
    if (requirementsDoc) {
      archive.append(requirementsDoc, { name: 'requirements.md' });
    }

    // Add all uploaded files in an assets folder
    const uploadsDir = path.join(__dirname, 'uploads');
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

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Root redirect
app.get('/', (req, res) => {
  if (req.cookies.authToken) {
    try {
      auth.authenticate(req, res, () => {
        return res.redirect(req.user.role === 'admin' ? '/admin' : '/dashboard');
      });
      return;
    } catch {}
  }
  res.redirect('/login');
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).render('error', { 
    message: 'Internal server error',
    user: req.user || null 
  });
});

// HTTP
app.listen(PORT, () => {
  console.log(`🎙️  VoiceReq AI running on http://localhost:${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/admin (luke@voicereq.ai / admin123)`);
});

// HTTPS
try {
  const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'certs', 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem')),
  };
  https.createServer(sslOptions, app).listen(HTTPS_PORT, () => {
    console.log(`🔒 HTTPS running on https://localhost:${HTTPS_PORT}`);
  });
} catch (e) {
  console.log('⚠️  No SSL certs, HTTPS disabled');
}