const express = require('express');
const path = require('path');
const fs = require('fs');
const https = require('https');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const ipaddr = require('ipaddr.js');
const otplib = require('otplib');
const qrcode = require('qrcode');
const nodemailer = require('nodemailer');

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
/* app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net", "https://vapi.ai", "https://*.vapi.ai"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://*.vapi.ai"],
      connectSrc: ["'self'", "https://api.vapi.ai", "wss://*.vapi.ai", "https://api.openai.com"],
      frameSrc: ["'self'", "https://*.vapi.ai"],
      mediaSrc: ["'self'", "blob:", "https://*.vapi.ai"],
      workerSrc: ["'self'", "blob:"]
    },
  },
})); */
app.use(helmet({
  contentSecurityPolicy: false
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

// Small HTML escape helper used when rendering extracted design snippets
function escapeHtml(s) {
  if (s === undefined || s === null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Lightweight summarizer for requirements -> return brief summary
function summarizeRequirements(text){
  const lines = (text||'').split(/\n+/).map(l=>l.trim()).filter(Boolean);
  // naive: take first 5 lines and join
  return lines.slice(0,5).join(' ');
}

// Build a simple wireframe HTML for the design proposal
function buildWireframeHtml(projectId, summary){
  return `
    <div style="font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial; color:#0f172a;">
      <h2 style="margin-bottom:6px">Proposed design for ${projectId}</h2>
      <p style="color:#475569">${escapeHtml(summary)}</p>
      <div style="margin-top:12px;padding:12px;border:1px dashed #cbd5e1;border-radius:8px;background:#fff">
        <div style="height:12px;background:#eef2ff;border-radius:6px;margin-bottom:10px;width:40%"></div>
        <div style="height:200px;border:1px solid #e2e8f0;border-radius:6px;display:flex;align-items:center;justify-content:center;color:#64748b">Wireframe placeholder (hero card + CTA)</div>
        <div style="display:flex;gap:8px;margin-top:12px">
          <div style="flex:1;height:40px;background:#667eea;border-radius:8px;color:white;display:flex;align-items:center;justify-content:center">Primary CTA</div>
          <div style="flex:1;height:40px;background:#e2e8f0;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#0f172a">Secondary</div>
        </div>
      </div>
    </div>
  `;
}

function generateFollowupQuestions(summary){
  // naive questions based on summary length and common gaps
  const qs = [
    'Confirm primary CTA and desired user action.',
    'Any branding or color guidelines to apply?',
    'Which data sources or files are authoritative for requirements?'
  ];
  return qs;
}


// Cloudflare-only Middleware
const cloudflareOnly = (req, res, next) => {
  // TEMPORARILY DISABLED TO DEBUG 502 ERROR
  return next();
};

// Security Alert Helper (Telegram)
async function sendSecurityAlert(type, details) {
  const message = 'SECURITY ALERT: Morti Projects\nType: ' + type + '\nTime: ' + new Date().toLocaleString() + '\nDetails: ' + JSON.stringify(details);

  try {
    await db.logAction(null, 'security_alert', { type, ...details }, details.ip || '0.0.0.0');
    const telegramBotToken = process.env.TELEGRAM_BOT_TOKEN || process.env.TELEGRAM_SECURITY_BOT_TOKEN;
    const telegramChatId = process.env.TELEGRAM_CHAT_ID || process.env.TELEGRAM_LUKE_CHAT_ID;
    if (telegramBotToken && telegramChatId) {
      const url = 'https://api.telegram.org/bot' + telegramBotToken + '/sendMessage';
      try {
        await fetch(url, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({chat_id: telegramChatId, text: message}) });
        console.log('[Security Alert Sent to Telegram]', type);
      } catch(err) { console.error('Telegram send failed:', err.message); }
    } else { console.warn('Telegram token/chat missing'); }
    console.log('[Security Alert]', type, details);
  } catch(e) { console.error('Failed to send security alert:', e.message); }
}

app.use(cloudflareOnly);
app.use(sanitizeInput);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// File upload setup — use persistent storage if available
let uploadsDir;
if (process.env.DATA_DIR) {
  try {
    fs.mkdirSync(process.env.DATA_DIR, { recursive: true });
    uploadsDir = path.join(process.env.DATA_DIR, 'uploads');
  } catch (e) {
    console.warn(`DATA_DIR ${process.env.DATA_DIR} not writable, using local uploads`);
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

// Ownership check: verify session or project belongs to the requesting user (admins bypass)
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
  const projectId = req.body.projectId || req.body.project_id || req.params.projectId;
  if (!projectId) return res.status(400).json({ error: 'Project ID required' });
  const project = await db.getProject(projectId);
  if (!project || project.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  next();
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

// Serve uploaded files (behind auth + ownership check)
app.use('/uploads', async (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).send('Unauthorized');
  try {
    const decoded = require('jsonwebtoken').verify(token, require('./auth').JWT_SECRET);
    const user = await db.getUserById(decoded.id);
    if (!user) return res.status(401).send('Unauthorized');
    // Admins can access all files
    if (user.role === 'admin') return next();
    // Customers: verify file belongs to their project
    const filename = decodeURIComponent(req.path.replace(/^\//, ''));
    const file = db.db.prepare('SELECT f.*, p.user_id FROM files f JOIN projects p ON f.project_id = p.id WHERE f.filename = ? OR f.original_name = ?').get(filename, filename);
    if (!file || file.user_id !== user.id) return res.status(403).send('Forbidden');
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

app.get('/login/mfa', async (req, res) => {
  const mfaPending = req.cookies.mfaPending;
  if (!mfaPending) return res.redirect('/login');
  res.render('login-mfa', { error: null });
});

app.post('/login/mfa', async (req, res) => {
  const mfaPending = req.cookies.mfaPending;
  if (!mfaPending) return res.redirect('/login');

  try {
    const decoded = require('jsonwebtoken').verify(mfaPending, auth.JWT_SECRET);
    const user = await db.getUserById(decoded.id);
    const { code } = req.body;

    const result = otplib.verifySync({ secret: user.mfa_secret, token: code });
    if (!result.valid) {
      sendSecurityAlert('Failed MFA Attempt', { email: user.email, ip: req.ip, userAgent: req.get('User-Agent') });
      return res.render('login-mfa', { error: 'Invalid verification code' });
    }

    // Successful MFA Login - alert and log
    sendSecurityAlert('Successful MFA Login', { email: user.email, ip: req.ip, userAgent: req.get('User-Agent') });
    await db.logAction(user.id, 'mfa_login', { email: user.email }, req.ip);

    const token = auth.generateToken(user);
    res.clearCookie('mfaPending');
    res.cookie('authToken', token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 2 * 60 * 60 * 1000 
    });
    
    res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
  } catch (e) {
    res.redirect('/login');
  }
});

// MFA enrollment prompt (shown after login for users without MFA)
app.get('/profile/mfa/prompt', auth.authenticate, async (req, res) => {
  res.render('mfa-prompt', { user: req.user });
});

app.get('/profile/mfa/setup', auth.authenticate, async (req, res) => {
  try {
    const user = await db.getUserById(req.user.id);
    if (!user) {
      console.error('MFA Setup: User not found in database', req.user.id);
      return res.redirect('/profile?error=User account not found');
    }

    if (user.mfa_secret) return res.redirect('/profile?message=MFA is already enabled');

    const secret = otplib.generateSecret();
    const otpauth = otplib.generateURI({ secret, issuer: 'Morti Projects', label: user.email, type: 'totp' });
    const qrCodeUrl = await qrcode.toDataURL(otpauth);
    
    res.render('mfa-setup', { 
      user: req.user,
      qrCodeUrl,
      secret,
      title: 'Setup 2FA',
      currentPage: 'profile'
    });
  } catch (err) {
    console.error('MFA Setup Error:', err);
    res.redirect(`/profile?error=Failed to initialize 2FA setup: ${err.message}`);
  }
});

app.post('/profile/mfa/setup', auth.authenticate, async (req, res) => {
  try {
    const { code, secret } = req.body;
    const result = otplib.verifySync({ secret, token: code });
    
    if (!result.valid) {
      const user = await db.getUserById(req.user.id);
      const otpauth = otplib.generateURI({ secret, issuer: 'Morti Projects', label: user.email, type: 'totp' });
      const qrCodeUrl = await qrcode.toDataURL(otpauth);
      return res.render('mfa-setup', { 
        user: req.user,
        qrCodeUrl,
        secret,
        error: 'Invalid code, please try again',
        title: 'Setup 2FA',
        currentPage: 'profile'
      });
    }

    await db.updateUserMfaSecret(req.user.id, secret);
    await db.logAction(req.user.id, 'mfa_enabled', {}, req.ip);
    
    res.redirect('/profile?message=Two-factor authentication enabled successfully');
  } catch (err) {
    res.redirect('/profile?error=Failed to enable 2FA');
  }
});

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

// Track failed logins per IP
const failedLogins = new Map();

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.getUser(email);
    
    // Check if account is pending approval
    if (user && user.approved === 0) {
      return res.render('login', { error: 'Your account is pending approval. We\'ll be in touch soon.', email });
    }

    if (!user || !auth.verifyPassword(password, user.password_hash)) {
      // Track failure
      const count = (failedLogins.get(req.ip) || 0) + 1;
      failedLogins.set(req.ip, count);
      
      if (count >= 5) {
        sendSecurityAlert('Brute Force Attempt', {
          email,
          ip: req.ip,
          attempts: count,
          userAgent: req.get('User-Agent')
        });
      }

      sendSecurityAlert('Failed Login Attempt', { email, ip: req.ip, userAgent: req.get('User-Agent') });
      return res.render('login', { error: 'Invalid email or password', email });
    }
    
    // Reset on success
    failedLogins.delete(req.ip);

    // Successful login - alert and log
    sendSecurityAlert('Successful Login', { email: user.email, ip: req.ip, userAgent: req.get('User-Agent') });
    await db.logAction(user.id, 'login', { email: user.email }, req.ip);

    // MFA Check
    if (user.mfa_secret) {
      // Store temporary session for MFA completion
      const mfaToken = require('jsonwebtoken').sign(
        { id: user.id, partial: true }, 
        auth.JWT_SECRET, 
        { expiresIn: '5m' }
      );
      res.cookie('mfaPending', mfaToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 300000 });
      return res.redirect('/login/mfa');
    }

    // Generate JWT for non-MFA login
    const token = require('jsonwebtoken').sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      auth.JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.cookie('authToken', token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 2 * 60 * 60 * 1000 // 2 hours
    });
    
    // Redirect non-MFA users to setup prompt
    if (!user.mfa_secret) {
      return res.redirect('/profile/mfa/prompt');
    }

    res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
  } catch (e) {
    console.error('Login error:', e);
    res.render('login', { error: 'Login failed', email: req.body.email || '' });
  }
});

app.get('/logout', async (req, res) => {
  res.clearCookie('authToken');
  res.clearCookie('mfaPending');
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

// Approve customer account
app.post('/admin/customers/:id/approve', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    db.getDb().prepare('UPDATE users SET approved = 1 WHERE id = ?').run(req.params.id);
    res.redirect('/admin/customers?message=Customer approved successfully');
  } catch (e) {
    console.error('Approve customer error:', e);
    res.redirect('/admin/customers?error=Failed to approve customer');
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

// Feature Request API
app.post('/api/feature-request', apiAuth, async (req, res) => {
  try {
    const { text, page } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Text is required' });
    const stmt = db.db.prepare('INSERT INTO feature_requests (user_id, user_name, user_email, text, page) VALUES (?, ?, ?, ?, ?)');
    stmt.run(req.user.id, req.user.name, req.user.email, text.trim(), page || 'unknown');
    // Telegram notification
    const tgToken = process.env.TELEGRAM_BOT_TOKEN;
    const tgChat = process.env.TELEGRAM_CHAT_ID;
    if (tgToken && tgChat) {
      const msg = `💡 Feature Request\nFrom: ${req.user.name} (${req.user.email})\nPage: ${page || 'unknown'}\n\n${text.trim()}`;
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
app.get('/admin/feature-requests', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const requests = db.db.prepare('SELECT * FROM feature_requests ORDER BY created_at DESC').all();
    res.render('admin/feature-requests', { user: req.user, requests, currentPage: 'admin-feature-requests' });
  } catch (e) {
    console.error('Feature requests page error:', e);
    res.status(500).send('Error loading feature requests');
  }
});

// Delete file (API - works from portal and session)
app.delete('/api/files/:id', apiAuth, verifyFileOwnership, async (req, res) => {
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
  
  // check for existing design
  const designsDir = DESIGNS_DIR;
  let designExists = false;
  try {
    if (fs.existsSync(designsDir)) {
      const files = fs.readdirSync(designsDir).filter(f => f.startsWith(`design-${req.params.id}-`));
      if (files.length > 0) {
        designExists = true;
        // build designs list with metadata
        const designsList = files.map(fn => {
          try { const d = JSON.parse(fs.readFileSync(path.join(designsDir, fn), 'utf8')); return { id: d.id || fn.replace('.json',''), file: fn, createdAt: d.createdAt || fs.statSync(path.join(designsDir, fn)).mtime.toISOString(), version: d.version || 1, status: d.status || 'draft', owner: d.owner || '' }; } catch(e) { return { id: fn.replace('.json',''), file: fn, createdAt: fs.statSync(path.join(designsDir, fn)).mtime.toISOString(), version: 1, status: 'draft', owner: '' }; }
        }).sort((a,b)=> new Date(b.createdAt)-new Date(a.createdAt));
        // attach to locals
        res.locals.designsList = designsList;
        try {
          const newestFile = designsList[0] && designsList[0].file;
          if (newestFile) {
            const newestDesign = JSON.parse(fs.readFileSync(path.join(designsDir, newestFile), "utf8"));
            res.locals.latestDesign = newestDesign;
          }
        } catch(e) {}
      }
    }
  } catch(e) { designExists = false; }
  // Get customer answers from latest design
  let customerAnswers = [];
  try {
    const designResult = loadNewestDesign(req.params.id);
    if (designResult && designResult.design && designResult.design.customerAnswers) {
      customerAnswers = designResult.design.customerAnswers;
    }
  } catch(e) {}

  res.render('admin/project-detail', {
    customerAnswers,
    designExists: designExists,
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


// Morti Projects: Design extraction and admin design view
app.post('/admin/projects/:id/extract-design', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const sessions = await db.getSessionsByProject(projectId);
    // aggregate transcript and file contents
    let reqText = '';
    sessions.forEach(s => {
      try {
        const t = JSON.parse(s.transcript || '[]');
        t.forEach(m => reqText += `${m.role}: ${m.text}
`);
      } catch {}
    });
    const files = await db.getFilesByProject(projectId);
    files.forEach(f => { 
      const text = (f.extracted_text || '').trim();
      if (text) {
        reqText += `\n\nUPLOADED FILE: ${f.original_name}\n${f.description ? 'Description: ' + f.description + '\n' : ''}Content:\n${text.substring(0, 5000)}\n`;
      } else {
        reqText += `\nUPLOADED FILE: ${f.original_name} (no text extracted)\n`;
      }
    });

    // Include admin notes
    const project = await db.getProject(projectId);
    try {
      const adminNotes = JSON.parse(project.admin_notes || '[]');
      if (adminNotes.length > 0) {
        reqText += '\n\nADMIN NOTES (additional context provided by the project administrator):\n';
        adminNotes.forEach(n => { reqText += `- ${n.text}\n`; });
      }
    } catch(e) {}

    // Use LLM (gpt-5-mini) to generate a structured solution design and follow-up questions
    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    let llmDesignMarkdown = '';
    let llmQuestions = generateFollowupQuestions(summarizeRequirements(reqText));
    let designVersion = 1;
    let designStatus = 'draft';
    let designParsedSections = null;
    let designSummary = '';

    const DESIGN_SECTIONS_SCHEMA = `{
  "summary": "3-5 sentence executive summary: what this system actually is, the core operating loop, what problem it solves, and what it is NOT.",
  "design": {
    "ExecutiveSummary": "Plain English explanation of what this system is. The core operating loop. What problem it solves and what it is not. Keep it commercially credible.",
    "CoreWorkflow": "Step-by-step operational flow in practical terms. For each step: why it exists, what value it adds, where human control remains. Avoid technical jargon.",
    "SimplifiedArchitecture": "Minimal viable architecture to deliver the workflow. Recommended tool categories (database, automation layer, LLM, external APIs) with rationale for each. Explicitly state what is NOT required for MVP. Avoid microservices, enterprise cloud discussions, advanced DevOps unless absolutely necessary.",
    "MinimalDataModel": "Only essential data structures. For each entity: name, key fields, purpose in the system, why it is needed. Keep it lean.",
    "ManualVsAutomated": "Clearly separate what remains manual by design vs what is automated, and why. Comment on strategic control and risk management.",
    "Assumptions": "Assumptions made in designing this MVP: user volume, budget constraints, data sensitivity, platform compliance, operational maturity. These justify architectural simplifications.",
    "Dependencies": "External dependencies: APIs, third-party tools, data sources, access credentials, user-provided inputs. Clarify which are critical vs optional.",
    "Phase2Enhancements": "OUT OF SCOPE for MVP. List enhancements that improve scale, analytics, automation, resilience. Make clear these are future considerations, not required for launch.",
    "RisksAndMitigations": "Realistic risks only — no theatrical or enterprise-only risks. For each: impact and lightweight mitigation suitable for MVP stage.",
    "BuildEffortEstimate": "Complexity rating (Low/Medium/High), rough timeline, key build phases. Be practical."
  },
  "questions": [
    {"id": 1, "text": "Specific question about a gap or ambiguity", "assumption": "What we'll assume if unanswered"}
  ]
}`;

    const DESIGN_RULES = `RULES:
- You are a pragmatic product architect. The requirements may be verbose, repetitive, or over-engineered. Your job is to SYNTHESIZE them into a commercially credible MVP design.
- Extract the true business objective. Preserve critical strategic control points (human decisions, approval loops, segmentation logic).
- Remove premature scaling, infrastructure complexity, and architectural over-design.
- Focus on a system that can realistically be built by a small team in under 4 weeks.
- Use off-the-shelf tools where possible. Assume early-stage deployment with limited users unless otherwise specified.
- Do NOT restate the requirements. Interpret them and produce a buildable design.
- ALL section values MUST be plain text strings (no nested JSON objects). Use "- " for lists, "1. " for sequences.
- Reference the specific tools, platforms, and workflows mentioned in the conversation.
- Where vague, make a reasonable assumption and mark it with [ASSUMPTION].

TONE: Clear, pragmatic, commercially credible. Avoid hype. Avoid enterprise theatre. Avoid unnecessary technical depth. Prioritize clarity and decision rationale. Write as if this document will be reviewed by a founder or commercial stakeholder, not an infrastructure committee.

DESIGN PRINCIPLES:
- Humans steer; systems automate repetition.
- Prove the loop before scaling.
- Use simplicity as a strategic advantage.
- Remove anything that does not directly create user value in MVP.`;

    // Build different prompts for first-run vs refresh
    const buildPrompt = (context, prevAnswers, previousDesign) => {
      if (!previousDesign) {
        // FIRST RUN: full extraction from conversation
        return `You are a pragmatic product architect and systems designer. You are given a raw requirements dataset from a client conversation. Your task is to synthesize those requirements into a commercially credible MVP design document.

OUTPUT FORMAT: Valid JSON only. No markdown wrapping. Structure:
${DESIGN_SECTIONS_SCHEMA}

${DESIGN_RULES}

QUESTIONS RULES (FIRST EXTRACTION):
- Generate questions ONLY for genuinely missing critical information that would block a small team from building this in 4 weeks.
- Questions MUST reference specific details from the conversation.
- BAD: "Any branding guidelines?", "What data sources?" — generic filler.
- GOOD: "You mentioned LinkedIn Sales Navigator — do you need real-time monitoring or is a daily batch sync sufficient for MVP?"
- Maximum 5 questions. If the conversation covers everything needed for MVP, return an EMPTY array [].
- Each question needs a unique sequential id starting from 1.

RAW REQUIREMENTS (conversation & files):
${context}`;
      } else {
        // REFRESH: update existing design with new information only
        return `You are a pragmatic product architect UPDATING an existing MVP design. A previous design already exists. Your job is to:

1. START with the previous design as the baseline — preserve all existing content.
2. INCORPORATE new information: answered questions, new admin notes, updated requirements.
3. REFINE sections affected by the new information.
4. DO NOT regenerate sections that haven't changed.
5. DO NOT ask new questions unless the new information reveals a genuinely critical gap for MVP delivery.

OUTPUT FORMAT: Valid JSON only. No markdown wrapping. Same structure:
${DESIGN_SECTIONS_SCHEMA}

${DESIGN_RULES}

QUESTIONS RULES (REFRESH — STRICT):
- Only ask NEW questions if the new information reveals a critical gap that blocks MVP build.
- Do NOT re-ask answered questions. Do NOT ask follow-ups to satisfactory answers.
- Prefer making an [ASSUMPTION] over asking another question.
- Maximum 3 new questions. Return EMPTY array [] if nothing critical is missing.
- If previous questions were answered satisfactorily, there should be ZERO new questions.

PREVIOUS DESIGN (baseline — preserve, update where new info applies):
${JSON.stringify(previousDesign.sections || {}, null, 2).substring(0, 20000)}

Previous Summary: ${previousDesign.summary || 'None'}

ANSWERED QUESTIONS (incorporate into design, do NOT re-ask):
${prevAnswers || 'None'}

NEW INFORMATION SINCE LAST DESIGN:
${context}`;
      }
    };

    // Load previous design for refresh mode
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

    // For refresh: build context of what's NEW since last design
    let promptContext = reqText.substring(0, 60000);
    if (previousDesign) {
      // On refresh, focus on new information
      const newInfo = [];
      if (prevAnswersText) newInfo.push('ANSWERED QUESTIONS:\n' + prevAnswersText);
      
      // Include accepted assumptions
      if (previousDesign.acceptedAssumptions && previousDesign.acceptedAssumptions.length > 0) {
        newInfo.push('ACCEPTED ASSUMPTIONS (incorporate these as decisions, do NOT re-ask):\n' + 
          previousDesign.acceptedAssumptions.map(a => `- Q: ${a.question} → Assumption accepted: ${a.assumption}`).join('\n'));
      }
      
      // Admin notes (all, since they may have been updated)
      try {
        const adminNotes = JSON.parse(project.admin_notes || '[]');
        if (adminNotes.length > 0) {
          newInfo.push('ADMIN NOTES:\n' + adminNotes.map(n => `- ${n.text}`).join('\n'));
        }
      } catch(e) {}
      
      // Include full transcript for context but mark it
      newInfo.push('FULL PROJECT TRANSCRIPT (for reference):\n' + reqText.substring(0, 40000));
      
      promptContext = newInfo.join('\n\n---\n\n');
    }

    if (OPENAI_KEY) {
      try {
        const prompt = buildPrompt(promptContext, prevAnswersText, previousDesign);
        const model = process.env.LLM_MODEL || process.env.OPENAI_MODEL || 'chatgpt-4o-latest';
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
          body: JSON.stringify({ model: model, max_completion_tokens: 8000, messages: [{ role: 'system', content: 'You are a senior solutions architect and business analyst. You produce detailed, actionable solution designs.' }, { role: 'user', content: prompt }] })
        });
        if (resp.ok) {
          const data = await resp.json();
          let content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
          // Parse JSON safely: try to extract JSON substring
          try {
            // Strip markdown code fences if present
            let cleanContent = content;
            if (cleanContent.includes('```json')) {
              cleanContent = cleanContent.replace(/```json\s*/g, '').replace(/```/g, '');
            }
            const jsonStart = cleanContent.indexOf('{');
            const jsonText = jsonStart >=0 ? cleanContent.slice(jsonStart) : cleanContent;
            const parsed = JSON.parse(jsonText);
            
            // Store raw parsed design object for structured rendering
            if (parsed.design && typeof parsed.design === 'object') {
              // Flatten any nested objects to readable text
              const flatDesign = {};
              for (const [key, val] of Object.entries(parsed.design)) {
                if (typeof val === 'string') {
                  flatDesign[key] = val;
                } else if (typeof val === 'object') {
                  // Convert nested objects/arrays to readable bullet points
                  const flatten = (obj, prefix = '') => {
                    let out = '';
                    if (Array.isArray(obj)) {
                      obj.forEach((item, i) => {
                        if (typeof item === 'object') out += flatten(item, `${i+1}. `);
                        else out += `- ${item}\n`;
                      });
                    } else {
                      for (const [k, v] of Object.entries(obj)) {
                        if (typeof v === 'object') { out += `\n${prefix}${k}:\n${flatten(v, '  ')}`; }
                        else { out += `${prefix}- ${k}: ${v}\n`; }
                      }
                    }
                    return out;
                  };
                  flatDesign[key] = flatten(val);
                } else {
                  flatDesign[key] = String(val);
                }
              }
              // Convert to markdown
              let md = '';
              for (const [section, body] of Object.entries(flatDesign)) {
                const title = section.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase()).trim();
                md += `## ${title}\n\n${body}\n\n`;
              }
              llmDesignMarkdown = md;
              designParsedSections = flatDesign;
            } else if (typeof parsed.design === 'string') {
              llmDesignMarkdown = parsed.design;
            }
            
            if (parsed.summary) {
              designSummary = parsed.summary;
            }
            
            if (parsed.questions && Array.isArray(parsed.questions)) {
              llmQuestions = parsed.questions;
            }
          } catch (e) {
            console.warn('JSON parse failed, using raw content:', e.message);
            // fallback: treat entire content as markdown
            llmDesignMarkdown = content || '';
          }
        } else {
          console.error('LLM call failed with status', resp.status);
        }
      } catch (e) { console.error('LLM call error:', e.message); }
    } else {
      // stub
      llmDesignMarkdown = `## Summary

${summarizeRequirements(reqText)}

## Architecture

- Backend: Express
- DB: SQLite/Postgres

## Components

- Proposal generator service

## Data Flow

- Input: project requirements -> generator -> proposal

## APIs

- /api/proposals/create

## Security

- JWT auth, HTTPS

## Acceptance Criteria

- Generates proposal, supports approval and signing.`;
    }

    // Defensive sanitization: remove verbatim transcript lines that start with user: or ai:
    llmDesignMarkdown = llmDesignMarkdown.replace(/^ *(user|ai|assistant):.*$/gmi, '').trim();

    // Minimal markdown -> HTML renderer (safe)
    function mdToHtml(md){
      if(!md) return '';
      let out = String(md || '');
      // basic escaping
      out = out.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      // simple headings
      out = out.replace(/^### (.*)$/gm, '<h3>$1</h3>');
      out = out.replace(/^## (.*)$/gm, '<h2>$1</h2>');
      out = out.replace(/^# (.*)$/gm, '<h1>$1</h1>');
      // paragraphs (split by double newlines)
      const paras = out.split(/\n\n+/).map(p=>p.trim()).filter(Boolean);
      out = paras.map(p => '<p>' + p.replace(/\n/g,'<br/>') + '</p>').join('\n');
      return out;
    }


    // versioning: if there is already a design, increment version
    try {
      const designsDirCheck = DESIGNS_DIR;
      if (fs.existsSync(designsDirCheck)) {
        const existing = fs.readdirSync(designsDirCheck).filter(f => f.startsWith(`design-${projectId}-`));
        if (existing.length > 0) {
          // find newest
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
      owner: req.user.email,
      version: designVersion,
      status: designStatus,
      summary: designSummary,
      designMarkdown: llmDesignMarkdown,
      designHtml: mdToHtml(llmDesignMarkdown),
      sections: designParsedSections,
      questions: llmQuestions,
      chat: [],
      answers: [],
      customerAnswers: [],
      raw_output: ''
    };

    // Carry forward state from previous design version
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
      }
    } catch(e) {}

    // If designMarkdown contains JSON-in-markdown, parse and populate top-level questions
    try {
      if (design.designMarkdown && String(design.designMarkdown).trim().startsWith('```json')) {
        const jsonText = String(design.designMarkdown).replace(/```json\s*|```/g, '').trim();
        try {
          const parsed = JSON.parse(jsonText);
          if (parsed.questions && Array.isArray(parsed.questions)) {
            design.questions = parsed.questions;
          }
          if (parsed.design) {
            // render parsed.design sections
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

    // Mirror questions to project record for easy lookup
    try {
      await db.updateProjectDesignQuestions(projectId, JSON.stringify(design.questions || []));
    } catch(e) { console.warn('Failed to update project.design_questions', e.message); }

    res.redirect(`/admin/projects/${projectId}?message=Design+extracted`);
  } catch (e) {
    console.error('Extract design error:', e);
    res.redirect(`/admin/projects/${req.params.id}?error=Design+extraction+failed`);
  }
});

app.get('/admin/projects/:id/design', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const designsDir = DESIGNS_DIR;
    if (!fs.existsSync(designsDir)) return res.status(404).send('No designs found');
    const candidates = fs.readdirSync(designsDir).filter(f => f.startsWith(`design-${projectId}-`));
    if (candidates.length === 0) return res.status(404).send('No design for project');
    // pick the newest design file by modified time
    let newest = candidates[0];
    let newestMtime = fs.statSync(path.join(designsDir, newest)).mtimeMs;
    for (const c of candidates) {
      const m = fs.statSync(path.join(designsDir, c)).mtimeMs;
      if (m > newestMtime) { newest = c; newestMtime = m; }
    }
    const design = JSON.parse(fs.readFileSync(path.join(designsDir, newest), 'utf8'));
    // If designMarkdown contains JSON in code fences, try to parse and build designHtml sections
    try {
      if (design.designMarkdown && design.designMarkdown.trim().startsWith('```json')) {
        const jsonText = design.designMarkdown.replace(/```json\s*|```/g, '').trim();
        try {
          const parsed = JSON.parse(jsonText);
          if (parsed && parsed.design) {
            // parsed.design may be object with sections
            const sections = parsed.design;
            let html = '';
            if (parsed.summary) html += `<h3>Summary</h3><p>${escapeHtml(parsed.summary)}</p>`;
            for (const [k,v] of Object.entries(sections)) {
              html += `<h3>${escapeHtml(k)}</h3><p>${escapeHtml(v)}</p>`;
            }
            design.designHtml = html;
          }
        } catch(e) { /* ignore parse errors */ }
      }
    } catch(e) { /* ignore */ }
    res.render('admin/project-design', { user: req.user, projectId, design, title: projectId + ' - Design' });
  } catch (e) {
    console.error('Get design error:', e);
    res.status(500).send('Failed to load design');
  }
});
// Helper: load newest design for a project
const DESIGNS_DIR = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'designs');

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

// Generate mermaid flowchart via OpenAI
app.post('/admin/projects/:id/design/flowchart', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const result = loadNewestDesign(req.params.id);
    if (!result) return res.status(404).json({ error: 'No design found' });
    const { design } = result;

    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (!OPENAI_KEY) return res.status(500).json({ error: 'OpenAI API key not configured' });

    // Build context from sections
    const sections = design.sections || {};
    const designContext = JSON.stringify({ summary: design.summary, sections }, null, 2);

    const prompt = `You are a systems architect creating a HIGH-LEVEL COMPONENT DIAGRAM. Given the solution design below, generate a Mermaid flowchart showing ONLY the system components and their first-level connections.

Rules:
- Use \`flowchart LR\` (left-to-right)
- Show ONLY system components being built and external services they connect to
- DO NOT show user actions, decision points, or user journeys
- This is a systems architecture diagram, not a process flow
- Each node = a system component, service, database, or external API
- Each edge = a data connection or integration between components
- Use labeled edges: A -->|"API call"| B
- Keep it simple: 8-15 nodes maximum
- Use subgraphs to group: "Our System" for components we build, "External" for third-party services
- Node shapes: [Component] for services, [(Database)] for data stores, [[External API]] for third-party
- ALWAYS wrap node labels in double quotes: A["Component Name"]
- Keep node IDs simple: A, B, C1, etc.
- Return ONLY mermaid code. No markdown fences, no explanation. Start with "flowchart LR".

Design:
${designContext.substring(0, 12000)}`;

    const resp = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
      body: JSON.stringify({
        model: 'chatgpt-4o-latest',
        max_completion_tokens: 2000,
        messages: [
          { role: 'system', content: 'You generate Mermaid flowchart diagrams. Return only valid mermaid syntax.' },
          { role: 'user', content: prompt }
        ]
      })
    });

    if (!resp.ok) throw new Error('OpenAI API returned ' + resp.status);
    const data = await resp.json();
    let mermaid = (data.choices[0].message.content || '').trim();
    // Strip any markdown fences
    mermaid = mermaid.replace(/^```(?:mermaid)?\s*/i, '').replace(/```\s*$/, '').trim();
    if (!mermaid.startsWith('flowchart')) mermaid = 'flowchart TD\n' + mermaid;
    
    // Sanitize node labels: wrap any label containing special chars in quotes
    // Match node definitions like A[Label] or A([Label]) or A{Label} etc.
    mermaid = mermaid.replace(/(\w+)(\[|\(|\{|\(\[|\[\()([^\]})]+)(\]|\)|\}|\]\)|\)\])/g, (match, id, open, label, close) => {
      // If label contains characters that break mermaid parsing, wrap in quotes
      if (/[\/\\(){}|<>#&]/.test(label) && !label.startsWith('"')) {
        label = '"' + label.replace(/"/g, "'") + '"';
      }
      return id + open + label + close;
    });

    // Save flowchart to design JSON
    try {
      const result = loadNewestDesign(req.params.id);
      if (result) {
        result.design.flowchart = mermaid;
        saveDesign(result.design);
      }
    } catch(e) { console.warn('Failed to save flowchart to design:', e.message); }

    res.json({ mermaid });
  } catch (e) { console.error('Flowchart error', e); res.status(500).json({ error: 'Failed to generate flowchart: ' + e.message }); }
});


app.post('/admin/projects/:id/design/chat', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const { designId, text } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Design not found' });
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    // Save user message
    const userEntry = { from: req.user.email, text, ts: new Date().toISOString() };
    design.chat = design.chat || [];
    design.chat.push(userEntry);

    // Call OpenAI gpt-5-mini with design context
    let aiText = '';
    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (OPENAI_KEY) {
      try {
        const designContext = JSON.stringify({ summary: design.summary, sections: design.sections, questions: design.questions, answers: design.answers }, null, 2).substring(0, 10000);
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

    // Save AI response
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
app.post('/admin/projects/:id/design/answer', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const { designId, question, answer } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).send('Design not found');
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    // store answer in design.answers
    design.answers = design.answers || [];
    design.answers.push({ question, answer, from: req.user.email, ts: new Date().toISOString() });
    fs.writeFileSync(filePath, JSON.stringify(design, null, 2));

    // also append to a session safely for audit
    try { await db.appendSessionMessageSafe(projectId, { role: 'admin', text: `Answer: ${question} -> ${answer}` }); } catch (e) { console.warn('appendSessionMessageSafe failed:', e.message); }

    // Redirect back to project detail so answers appear in the Design Questions area
    res.redirect(`/admin/projects/${projectId}?message=Answer+saved`);
  } catch (e) {
    console.error('Design answer error:', e);
    res.redirect(`/admin/projects/${req.params.id}/design?error=Save+failed`);
  }
});

// Publish design to customer
app.post('/admin/projects/:id/design/publish', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const result = loadNewestDesign(req.params.id);
    if (!result) return res.status(404).send('No design found');
    const { design } = result;
    design.published = true;
    design.publishedAt = new Date().toISOString();
    saveDesign(design);
    res.redirect(`/admin/projects/${req.params.id}/design?message=Design+published`);
  } catch (e) {
    console.error('Publish error:', e);
    res.redirect(`/admin/projects/${req.params.id}/design?error=Publish+failed`);
  }
});

// Admin notes for project
app.post('/admin/projects/:id/notes', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const { note } = req.body;
    if (!note || !note.trim()) return res.redirect(`/admin/projects/${projectId}`);
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).send('Project not found');
    let notes = [];
    try { notes = JSON.parse(project.admin_notes || '[]'); } catch(e) {}
    notes.push({ text: note.trim(), from: req.user.email, ts: new Date().toISOString() });
    await db.updateProjectAdminNotes(projectId, JSON.stringify(notes));
    res.redirect(`/admin/projects/${projectId}?message=Note+added`);
  } catch (e) {
    console.error('Add note error:', e);
    res.redirect(`/admin/projects/${req.params.id}?error=Failed+to+add+note`);
  }
});

app.post('/admin/projects/:id/notes/:noteIndex/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const noteIndex = parseInt(req.params.noteIndex);
    const project = await db.getProject(projectId);
    let notes = [];
    try { notes = JSON.parse(project.admin_notes || '[]'); } catch(e) {}
    notes.splice(noteIndex, 1);
    await db.updateProjectAdminNotes(projectId, JSON.stringify(notes));
    res.redirect(`/admin/projects/${projectId}?message=Note+deleted`);
  } catch (e) {
    res.redirect(`/admin/projects/${req.params.id}?error=Failed+to+delete+note`);
  }
});

app.post('/admin/projects/:id/design/unpublish', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const result = loadNewestDesign(req.params.id);
    if (!result) return res.status(404).send('No design found');
    const { design } = result;
    design.published = false;
    design.publishedAt = null;
    saveDesign(design);
    res.redirect(`/admin/projects/${req.params.id}/design?message=Design+unpublished`);
  } catch (e) {
    console.error('Unpublish error:', e);
    res.redirect(`/admin/projects/${req.params.id}/design?error=Unpublish+failed`);
  }
});

// Delete a design version
app.post('/admin/projects/:id/design/:designId/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const filePath = path.join(DESIGNS_DIR, req.params.designId + '.json');
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    res.redirect(`/admin/projects/${req.params.id}?message=Design+deleted`);
  } catch (e) {
    console.error('Delete design error:', e);
    res.redirect(`/admin/projects/${req.params.id}?error=Delete+failed`);
  }
});

// Accept assumption (move question to assumptions)
app.post('/admin/projects/:id/design/accept-assumption', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { designId, questionText, assumption } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Design not found' });
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    
    // Add to accepted assumptions
    design.acceptedAssumptions = design.acceptedAssumptions || [];
    design.acceptedAssumptions.push({ question: questionText, assumption, acceptedBy: req.user.email, ts: new Date().toISOString() });
    
    // Remove from questions list
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
app.post('/admin/projects/:id/design/assign-question', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const { designId, questionText, assignedTo } = req.body;
    const designsDir = DESIGNS_DIR;
    const filePath = path.join(designsDir, designId + '.json');
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Design not found' });
    const design = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    // Update question assignment
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
app.get('/customer/projects/:id/design', auth.authenticate, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).send('Project not found');
    // Customers can only see their own projects
    if (req.user.role === 'customer' && project.user_id !== req.user.id) return res.status(403).send('Forbidden');

    const result = loadNewestDesign(projectId);
    if (!result || !result.design.published) return res.status(404).send('No published design available');
    const { design } = result;

    res.render('customer/project-design', { user: req.user, projectId, project, design, title: project.name + ' - Design' });
  } catch (e) {
    console.error('Customer design view error:', e);
    res.status(500).send('Failed to load design');
  }
});

// Customer: answer assigned question
app.post('/customer/projects/:id/design/answer', auth.authenticate, async (req, res) => {
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

    res.redirect(`/projects/${projectId}`);
  } catch (e) {
    console.error('Customer answer error:', e);
    res.status(500).send('Failed to save answer');
  }
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

app.get('/profile', auth.authenticate, async (req, res) => {
  const fullUser = await db.getUserById(req.user.id) || req.user;
  res.render('profile', {
    user: { ...req.user, mfa_secret: fullUser.mfa_secret },
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
  
  // Check for published design and customer questions
  let hasPublishedDesign = false;
  let customerQuestions = [];
  let customerDesignId = '';
  let customerAnswers = [];
  try {
    const designResult = loadNewestDesign(req.params.id);
    if (designResult && designResult.design) {
      if (designResult.design.published) hasPublishedDesign = true;
      customerDesignId = designResult.design.id || '';
      customerAnswers = designResult.design.customerAnswers || [];
      if (designResult.design.questions && Array.isArray(designResult.design.questions)) {
        customerQuestions = designResult.design.questions.filter(q => q.assignedTo === 'customer');
      }
    }
  } catch(e) {}

  res.render('customer/project', {
    user: req.user,
    project,
    sessions,
    files,
    activeSession,
    hasPublishedDesign,
    customerQuestions,
    customerDesignId,
    customerAnswers,
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
                model: process.env.LLM_MODEL || 'chatgpt-4o-latest',
        
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
        model: process.env.LLM_MODEL || 'chatgpt-4o-latest',

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
app.put('/api/files/:id/description', apiAuth, express.json(), verifyFileOwnership, async (req, res) => {
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
        model: process.env.LLM_MODEL || 'chatgpt-4o-latest',

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
    "Data & Content": ["What data is involved, its sources, formats, volumes, and how it should be managed"]
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
    const content = data.choices[0].message.content;
    if (!content) {
      console.error('OpenAI returned empty content. Usage:', JSON.stringify(data.usage));
      throw new Error('Model returned empty content — try a different model');
    }
    const analysis = JSON.parse(content);
    
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
        model: process.env.LLM_MODEL || 'chatgpt-4o-latest',

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
app.get('/api/sessions/:id', apiAuth, verifySessionOwnership, async (req, res) => {
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

app.put('/api/sessions/:id', apiAuth, express.json({ limit: '10mb' }), verifySessionOwnership, async (req, res) => {
  try {
    const { transcript, requirements, context, status } = req.body;
    await db.updateSession(req.params.id, transcript, requirements, context, status || 'active');
    res.json({ success: true });
  } catch (e) {
    console.error('Update session error:', e);
    res.status(500).json({ error: 'Failed to update session' });
  }
});

// POST /save endpoint for sendBeacon (page unload) — sendBeacon only sends POST
app.post('/api/sessions/:id/save', apiAuth, express.json({ limit: '10mb' }), verifySessionOwnership, async (req, res) => {
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

// Import project from ZIP (reverse of export)
const importUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });
app.post('/admin/import-project', auth.authenticate, auth.requireAdmin, importUpload.single('zipfile'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send('No file uploaded');

    const zip = new AdmZip(req.file.buffer);
    const entries = zip.getEntries();

    // Parse requirements.md if present
    let requirementsDoc = '';
    let projectName = 'Imported Project';
    let projectDescription = '';
    const assetFiles = [];

    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const name = entry.entryName;

      if (name === 'requirements.md' || name.endsWith('/requirements.md')) {
        requirementsDoc = entry.getData().toString('utf8');
        // Try to extract project name from markdown header
        const nameMatch = requirementsDoc.match(/^#\s+(.+?)(?:\s*-\s*Requirements|\s*$)/m);
        if (nameMatch) projectName = nameMatch[1].trim();
        // Try to extract company
        const companyMatch = requirementsDoc.match(/\*\*Company:\*\*\s*(.+)/);
        if (companyMatch) projectDescription = companyMatch[1].trim();
      } else if (name.startsWith('assets/') || name.startsWith('files/')) {
        assetFiles.push({ name: path.basename(name), data: entry.getData(), size: entry.header.size });
      }
    }

    // Use provided name/description from form if given
    if (req.body.projectName) projectName = req.body.projectName;
    if (req.body.projectDescription) projectDescription = req.body.projectDescription;

    // Use the logged-in admin user
    const adminUser = req.user || { id: 1 };

    // Build a proper description from parsed requirements if none provided
    if (!projectDescription && requirementsDoc) {
      // Use first paragraph or company line as description
      const companyMatch = requirementsDoc.match(/\*\*Company:\*\*\s*(.+)/);
      const firstPara = requirementsDoc.split('\n\n').find(p => p && !p.startsWith('#') && !p.startsWith('*') && !p.startsWith('-'));
      projectDescription = companyMatch ? companyMatch[1].trim() : (firstPara ? firstPara.trim().substring(0, 200) : 'Imported from ZIP');
    }

    // Create project
    const result = await db.createProject(adminUser.id, projectName, projectDescription || 'Imported from ZIP');
    const projectId = result.lastInsertRowid || result.id;

    // Create a session with the requirements
    if (requirementsDoc) {
      // Parse requirements sections from markdown
      const requirements = {};
      const sectionRegex = /###\s+(.+)\n([\s\S]*?)(?=###|## |$)/g;
      let match;
      while ((match = sectionRegex.exec(requirementsDoc)) !== null) {
        const section = match[1].trim();
        const items = match[2].split('\n').filter(l => l.startsWith('- ')).map(l => l.replace(/^- /, '').trim());
        if (items.length > 0) requirements[section] = items;
      }

      // Extract transcript if present
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

      // Update the session with parsed requirements and transcript
      const sessions = await db.getSessionsByProject(projectId);
      if (sessions.length > 0) {
        const sid = sessions[0].id;
        await db.updateSession(sid, transcript, requirements, {}, 'completed');
      }
    }

    // Save asset files
    if (assetFiles.length > 0) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      const sessions = await db.getSessionsByProject(projectId);
      const sessionId = sessions.length > 0 ? sessions[0].id : null;

      for (const asset of assetFiles) {
        const filename = Date.now() + '-' + asset.name;
        const filePath = path.join(uploadsDir, filename);
        fs.writeFileSync(filePath, asset.data);

        // Register in DB
        db.createFile(projectId, sessionId, filename, asset.name, '', asset.size, '', '');
      }
    }

    console.log(`📦 Imported project "${projectName}" (ID: ${projectId}) with ${assetFiles.length} assets`);
    res.redirect('/admin/projects/' + projectId);
  } catch (e) {
    console.error('Import error:', e);
    res.status(500).send('Import failed: ' + e.message);
  }
});

// Import ZIP into existing project (from project detail page)
app.post('/admin/projects/:id/import', auth.authenticate, auth.requireAdmin, importUpload.single('zipfile'), async (req, res) => {
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
      // Handle literal \n in exported files
      requirementsDoc = requirementsDoc.replace(/\\n/g, '\n');

      // Parse requirements sections
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

      // Parse transcript
      const transcript = [];
      const tSection = requirementsDoc.match(/## Full (?:Conversation History|Transcript)\n\n([\s\S]*?)(?=\n---|$)/);
      if (tSection) {
        const msgRegex = /\*\*(\w+):\*\*\s*([\s\S]*?)(?=\n\n\*\*\w+:\*\*|$)/g;
        let m;
        while ((m = msgRegex.exec(tSection[1])) !== null) {
          transcript.push({ role: m[1].toLowerCase() === 'ai' ? 'ai' : 'user', text: m[2].trim() });
        }
      }

      // Get or create session for this project
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

    // Save asset files
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

    res.redirect('/admin/projects/' + projectId);
  } catch (e) {
    console.error('Project import error:', e);
    res.status(500).send('Import failed: ' + e.message);
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Protected backup endpoint — dumps all data as JSON
app.get('/api/backup', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const backupKey = req.query.key;
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
    // Load design files
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

// Signup page
app.get('/signup', (req, res) => {
  res.render('signup');
});

const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: 'Too many signup attempts, please try again later.' });

app.post('/signup', signupLimiter, async (req, res) => {
  try {
    const { name, company, phone, email, password, password2 } = req.body;
    if (!name || !company || !phone || !email || !password || !password2) {
      return res.render('signup', { error: 'Please fill in all fields.', formData: req.body });
    }
    if (password !== password2) {
      return res.render('signup', { error: 'Passwords do not match.', formData: req.body });
    }
    if (password.length < 8) {
      return res.render('signup', { error: 'Password must be at least 8 characters.', formData: req.body });
    }

    // Check if email already exists
    const existing = await db.getUser(email);
    if (existing) {
      return res.render('signup', { error: 'An account with this email already exists.', formData: req.body });
    }

    // Create user with approved = 0 (pending)
    const bcrypt = require('bcryptjs');
    const hashedPassword = bcrypt.hashSync(password, 10);
    const stmt = db.getDb().prepare(`
      INSERT INTO users (email, password_hash, name, company, phone, role, approved)
      VALUES (?, ?, ?, ?, ?, 'customer', 0)
    `);
    stmt.run(email, hashedPassword, name, company, phone);

    // Telegram notification
    const tgToken = process.env.TELEGRAM_BOT_TOKEN;
    const tgChat = process.env.TELEGRAM_CHAT_ID;
    if (tgToken && tgChat) {
      try {
        const tgMsg = `🆕 New signup request!\n\nName: ${name}\nCompany: ${company}\nEmail: ${email}\nPhone: ${phone}\n\nAccount is pending approval.`;
        await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: tgChat, text: tgMsg })
        });
      } catch (err) {
        console.error('Telegram notify failed:', err.message);
      }
    }

    res.render('signup', { success: true });
  } catch (e) {
    console.error('Signup error:', e);
    res.render('signup', { error: 'Something went wrong. Please try again.', formData: req.body });
  }
});

// About page
app.get('/about', (req, res) => {
  res.render('about');
});

// Contact page
app.get('/contact', (req, res) => {
  res.render('contact');
});

const contactLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: 'Too many enquiries, please try again later.' });

app.post('/contact', contactLimiter, async (req, res) => {
  const { name, email, company, subject, message } = req.body;
  if (!name || !email || !message) {
    return res.render('contact', { error: 'Please fill in all required fields.', formData: req.body });
  }

  const subjectLabels = { general: 'General Enquiry', 'new-project': 'New Project', quote: 'Request a Quote', support: 'Existing Project Support' };
  const subjectLine = `[Morti Projects] ${subjectLabels[subject] || 'Enquiry'} from ${name}`;
  const body = `Name: ${name}\nEmail: ${email}\nCompany: ${company || 'N/A'}\nType: ${subjectLabels[subject] || subject}\n\nMessage:\n${message}`;

  // Save to file as backup
  const enquiriesDir = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'enquiries');
  if (!fs.existsSync(enquiriesDir)) fs.mkdirSync(enquiriesDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  fs.writeFileSync(path.join(enquiriesDir, `enquiry-${timestamp}.txt`), `${subjectLine}\nDate: ${new Date().toISOString()}\n\n${body}`);

  // Send email if SMTP configured
  const smtpUser = process.env.SMTP_USER || process.env.CONTACT_EMAIL;
  const smtpPass = process.env.SMTP_PASS;
  const contactTo = process.env.CONTACT_EMAIL || 'luke.mccarthy.home@gmail.com';

  if (smtpUser && smtpPass) {
    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: smtpUser, pass: smtpPass }
      });
      await transporter.sendMail({
        from: `"Morti Projects" <${smtpUser}>`,
        to: contactTo,
        replyTo: email,
        subject: subjectLine,
        text: body
      });
    } catch (err) {
      console.error('Email send failed:', err.message);
      // Still show success — enquiry saved to file
    }
  }

  // Also send Telegram notification
  const tgToken = process.env.TELEGRAM_BOT_TOKEN;
  const tgChat = process.env.TELEGRAM_CHAT_ID;
  if (tgToken && tgChat) {
    try {
      const tgMsg = `📬 New enquiry from ${name} (${email})${company ? ' — ' + company : ''}\n\n${subjectLabels[subject] || subject}: ${message.substring(0, 500)}`;
      await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: tgChat, text: tgMsg })
      });
    } catch (err) {
      console.error('Telegram notify failed:', err.message);
    }
  }

  res.render('contact', { success: true });
});

// Root redirect
app.get('/', (req, res) => {
  let isLoggedIn = false;
  let dashboardUrl = '/dashboard';
  if (req.cookies.authToken) {
    try {
      const jwt = require('jsonwebtoken');
      const decoded = jwt.verify(req.cookies.authToken, process.env.JWT_SECRET || 'your-secret-key');
      isLoggedIn = true;
      dashboardUrl = decoded.role === 'admin' ? '/admin' : '/dashboard';
    } catch {}
  }
  res.render('landing', { isLoggedIn, dashboardUrl });
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
    https.createServer(sslOptions, app).listen(HTTPS_PORT, '0.0.0.0', () => {
      console.log(`🔒 HTTPS running on https://192.168.1.178:${HTTPS_PORT}`);
    });
  } catch (e) {
    console.log('⚠️  No SSL certs, HTTPS disabled');
  }
});