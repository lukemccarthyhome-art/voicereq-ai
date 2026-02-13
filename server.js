const express = require('express');
const path = require('path');
const fs = require('fs');
const https = require('https');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const archiver = require('archiver');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss');

require('dotenv').config();

// Import database and authentication
const db = require('./database-adapter');
const auth = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = 3443;

// Trust proxy (Render terminates SSL at load balancer)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://vapi.ai", "https://*.vapi.ai"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://*.vapi.ai"],
      connectSrc: ["'self'", "https://api.vapi.ai", "wss://*.vapi.ai", "https://api.openai.com"],
      frameSrc: ["'self'", "https://*.vapi.ai"],
      mediaSrc: ["'self'", "blob:", "https://*.vapi.ai"]
    },
  },
}));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300, message: 'Too many requests' }));

// Stricter rate limit for file uploads
const uploadLimiter = rateLimit({ 
  windowMs: 60 * 60 * 1000, 
  max: 20, 
  message: 'File upload limit reached (20 files per hour). Please try again later.' 
});

// Stricter rate limit on login
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Too many login attempts' });

// Middleware
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Input Sanitization Middleware
const sanitizeInput = (req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key]);
      }
    }
  }
  next();
};
app.use(sanitizeInput);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// File upload setup — use persistent storage if available
// Use DATA_DIR if set AND writable, otherwise fall back to local
let uploadsDir;
if (process.env.DATA_DIR) {
  try {
    fs.mkdirSync(process.env.DATA_DIR, { recursive: true });
    uploadsDir = path.join(process.env.DATA_DIR, 'uploads');
  } catch (e) {
    console.warn(`⚠️  DATA_DIR ${process.env.DATA_DIR} not writable, using local uploads`);
    uploadsDir = path.join(__dirname, 'uploads');
  }
} else {
  uploadsDir = path.join(__dirname, 'uploads');
}
const upload = multer({ 
  dest: uploadsDir,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Ensure directories exist
fs.mkdirSync(uploadsDir, { recursive: true });

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

// Serve uploaded files (behind auth)
app.use('/uploads', (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).send('Unauthorized');
  try {
    require('jsonwebtoken').verify(token, require('./auth').JWT_SECRET);
    next();
  } catch { res.status(401).send('Unauthorized'); }
}, express.static(uploadsDir));
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });

// Serve static files with no-cache
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  setHeaders: (res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  }
}));

// === AUTHENTICATION ROUTES ===

app.get('/login', async (req, res) => {
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

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.getUser(email);
    
    if (!user || !auth.verifyPassword(password, user.password_hash)) {
      return res.render('login', { error: 'Invalid email or password', email });
    }
    
    const token = auth.generateToken(user);
    await db.logAction(user.id, 'login', { email: user.email }, req.ip);
    res.cookie('authToken', token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 2 * 60 * 60 * 1000 // 2 hours
    });
    
    res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
  } catch (e) {
    console.error('Login error:', e);
    res.render('login', { error: 'Login failed', email: req.body.email || '' });
  }
});

app.get('/logout', async (req, res) => {
  res.clearCookie('authToken');
  res.redirect('/login');
});

// === ADMIN ROUTES ===

app.get('/admin', auth.authenticate, auth.requireAdmin, async (req, res) => {
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

app.get('/admin/customers', auth.authenticate, auth.requireAdmin, async (req, res) => {
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

app.post('/admin/customers', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { name, email, company, password } = req.body;
    const finalPassword = password || Math.random().toString(36).slice(-8);
    
    await db.createUser(email, name, company, 'customer', finalPassword);
    res.redirect('/admin/customers?message=Customer created successfully');
  } catch (e) {
    console.error('Create customer error:', e);
    res.redirect('/admin/customers?error=Failed to create customer');
  }
});

app.post('/admin/customers/:id', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { name, email, company } = req.body;
    await db.updateUser(req.params.id, email, name, company);
    res.redirect('/admin/customers?message=Customer updated successfully');
  } catch (e) {
    console.error('Update customer error:', e);
    res.redirect('/admin/customers?error=Failed to update customer');
  }
});

app.post('/admin/customers/:id/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    await db.deleteUser(req.params.id);
    res.redirect('/admin/customers?message=Customer deleted successfully');
  } catch (e) {
    console.error('Delete customer error:', e);
    res.redirect('/admin/customers?error=Failed to delete customer');
  }
});

// Delete project (admin)
app.post('/admin/projects/:id/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
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

// Delete file (API - works from portal and session)
app.delete('/api/files/:id', apiAuth, async (req, res) => {
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

// Delete project (customer)
app.post('/projects/:id/delete', auth.authenticate, auth.requireCustomer, async (req, res) => {
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

app.get('/admin/projects', auth.authenticate, auth.requireAdmin, async (req, res) => {
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

app.get('/admin/projects/:id', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) {
    return res.status(404).send('Project not found');
  }
  
  const sessions = await db.getSessionsByProject(req.params.id);
  const files = await db.getFilesByProject(req.params.id);
  
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

// Admin: Reset customer password
app.post('/admin/customers/:id/password', auth.authenticate, auth.requireAdmin, async (req, res) => {
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

// === PROFILE ROUTES (for both admin and customer) ===

app.get('/profile', auth.authenticate, (req, res) => {
  res.render('profile', {
    user: req.user,
    title: 'Profile Settings',
    currentPage: req.user.role === 'admin' ? 'admin-profile' : 'customer-profile',
    message: req.query.message,
    error: req.query.error
  });
});

app.post('/profile/password', auth.authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    // Validate inputs
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.redirect('/profile?error=All password fields are required');
    }
    
    if (newPassword !== confirmPassword) {
      return res.redirect('/profile?error=New passwords do not match');
    }
    
    if (newPassword.length < 6) {
      return res.redirect('/profile?error=New password must be at least 6 characters');
    }
    
    // Verify current password
    const user = await db.getUserById(req.user.id);
    if (!auth.verifyPassword(currentPassword, user.password_hash)) {
      return res.redirect('/profile?error=Current password is incorrect');
    }
    
    // Update password
    const hashedPassword = auth.hashPassword(newPassword);
    await db.updateUserPassword(req.user.id, hashedPassword);
    
    res.redirect('/profile?message=Password updated successfully');
  } catch (e) {
    console.error('Update password error:', e);
    res.redirect('/profile?error=Failed to update password');
  }
});

// === CUSTOMER ROUTES ===

app.get('/dashboard', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const projects = await db.getProjectsByUser(req.user.id);
  res.render('customer/dashboard', {
    user: req.user,
    projects,
    title: 'Dashboard',
    currentPage: 'customer-dashboard',
    breadcrumbs: [{ name: 'Dashboard' }]
  });
});

app.get('/projects', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const projects = await db.getProjectsByUser(req.user.id);
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

app.get('/projects/new', auth.authenticate, auth.requireCustomer, async (req, res) => {
  res.redirect('/projects?new=true');
});

app.post('/projects', auth.authenticate, auth.requireCustomer, async (req, res) => {
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

app.get('/projects/:id', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project || project.user_id !== req.user.id) {
    return res.status(404).send('Project not found');
  }
  
  const sessions = await db.getSessionsByProject(req.params.id);
  const files = await db.getFilesByProject(req.params.id);
  const activeSession = await db.getLatestSessionForProject(req.params.id);
  
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

app.get('/projects/:id/session', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project || project.user_id !== req.user.id) {
    return res.status(404).send('Project not found');
  }
  
  // Check for existing active session
  let activeSession = await db.getLatestSessionForProject(req.params.id);
  if (!activeSession || activeSession.status === 'completed') {
    // Create new session
    const result = await db.createSession(req.params.id);
    activeSession = { id: result.lastInsertRowid };
  }
  
  res.redirect(`/voice-session?project=${req.params.id}&session=${activeSession.id}`);
});

app.get('/voice-session', auth.authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'voice-session.html'));
});

// === API ROUTES ===

// File upload and text extraction endpoint
app.post('/api/upload', apiAuth, uploadLimiter, upload.single('file'), async (req, res) => {
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
        // result is { pages: [{ text: "..." }, ...] }
        if (result && result.pages) {
          content = result.pages.map(p => p.text).join('\n\n');
        } else if (typeof result === 'string') {
          content = result;
        } else {
          content = JSON.stringify(result);
        }
      } catch (e) {
        console.log('pdf-parse error:', e.message);
        content = '[PDF: ' + file.originalname + ' — failed to extract text: ' + e.message + ']';
      }
    } else {
      content = '[File: ' + file.originalname + ' (' + ext + ') — unsupported format for text extraction]';
    }

    // Keep the file — rename to original name
    const savedPath = path.join(uploadsDir, file.originalname);
    fs.renameSync(filePath, savedPath);

    // Truncate if very long
    if (content.length > 8000) {
      content = content.substring(0, 8000) + '\n\n[...truncated, ' + content.length + ' total characters]';
    }

    // Save to database if project/session provided
    const { projectId, sessionId } = req.body;
    let fileId = null;
    let description = '';
    
    if (projectId) {
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
                model: 'gpt-3.5-turbo',
                temperature: 0.3,
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
              // Update file with description
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
app.post('/api/analyze', apiAuth, express.json({ limit: '10mb' }), async (req, res) => {
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
app.put('/api/files/:id/description', apiAuth, express.json(), async (req, res) => {
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

// Analyze full session (conversation + files) for comprehensive requirements extraction
app.post('/api/analyze-session', apiAuth, express.json({ limit: '20mb' }), async (req, res) => {
  try {
    const { transcript, fileContents, sessionId, projectId, existingRequirements } = req.body;
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
    let filesToAnalyze = fileContents;
    
    // Load files from DB for descriptions and as fallback for content
    let dbFiles = [];
    if (sessionId) {
      dbFiles = await db.getFilesBySession(sessionId) || [];
    }
    
    // If no fileContents provided, use DB extracted text as fallback
    if ((!fileContents || Object.keys(fileContents).length === 0) && dbFiles.length > 0) {
      filesToAnalyze = {};
      dbFiles.forEach(file => {
        if (file.extracted_text) {
          filesToAnalyze[file.original_name] = file.extracted_text;
        }
      });
    }
    
    if (filesToAnalyze && Object.keys(filesToAnalyze).length > 0) {
      analysisContent += '## UPLOADED DOCUMENTS\n\n';
      for (const [filename, content] of Object.entries(filesToAnalyze)) {
        // Include the AI-generated description for additional context
        const dbFile = dbFiles.find(f => f.original_name === filename);
        if (dbFile && dbFile.description) {
          analysisContent += `### ${filename}\n**Document Context:** ${dbFile.description}\n\n${content}\n\n---\n\n`;
        } else {
          analysisContent += `### ${filename}\n\n${content}\n\n---\n\n`;
        }
      }
    }
    
    // Add existing requirements so AI knows what's already captured
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
        model: 'gpt-3.5-turbo',
        temperature: 0.3,
        max_tokens: 4000,
        messages: [{
          role: 'system',
          content: `You are an expert business analyst conducting requirements analysis. Analyze the provided conversation transcript and uploaded documents to extract NEW requirements not already captured.

CRITICAL: A section titled "ALREADY CAPTURED REQUIREMENTS" lists requirements that have already been identified. DO NOT repeat or rephrase any of these. ONLY return genuinely NEW requirements, additional details, or refinements discovered in the latest conversation or documents. If nothing new is found for a category, omit that category entirely.

Focus on extracting clear, actionable requirements - not just restating what was said. Convert conversational statements into formal requirements.

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

// Text chat API - for standalone chat when not in voice call
app.post('/api/chat', apiAuth, express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { message, transcript, fileContents, sessionId } = req.body;
    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    
    if (!OPENAI_KEY) {
      return res.status(500).json({ error: 'OpenAI API key not configured' });
    }

    // Build context from transcript and files
    let contextContent = '';
    
    // Add file contents if available
    if (fileContents && Object.keys(fileContents).length > 0) {
      contextContent += '\n\n=== UPLOADED DOCUMENTS ===\n';
      Object.entries(fileContents).forEach(([filename, content]) => {
        contextContent += `\n--- ${filename} ---\n${content}\n`;
      });
    }
    
    // Add conversation history if available
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
        model: 'gpt-3.5-turbo',
        temperature: 0.7,
        messages: [{
          role: 'system',
          content: `You are an expert business analyst helping with requirements gathering and project analysis. You have access to uploaded documents and conversation history for context.
          
          Your role:
          - Help clarify and refine business requirements
          - Ask insightful follow-up questions
          - Identify gaps or inconsistencies in requirements
          - Suggest best practices and considerations
          - Be conversational but professional
          
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

// Session management API
app.get('/api/sessions/:id', apiAuth, async (req, res) => {
  try {
    const session = await db.getSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    // Also get associated files
    const files = await db.getFilesBySession(req.params.id);
    session.files = files;
    
    res.json(session);
  } catch (e) {
    console.error('Get session error:', e);
    res.status(500).json({ error: 'Failed to get session' });
  }
});

app.put('/api/sessions/:id', apiAuth, express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const { transcript, requirements, context, status } = req.body;
    await db.updateSession(req.params.id, transcript, requirements, context, status || 'active');
    res.json({ success: true });
  } catch (e) {
    console.error('Update session error:', e);
    res.status(500).json({ error: 'Failed to update session' });
  }
});

// Download all assets + requirements as zip
app.post('/api/export-zip', apiAuth, express.json({ limit: '10mb' }), async (req, res) => {
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
    // uploadsDir already defined at top
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

// Wait for database to be ready, then start server
db.ready.then(() => {
  // HTTP
  app.listen(PORT, () => {
    console.log(`🎙️  Morti Projects running on http://localhost:${PORT}`);
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
});