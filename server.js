const express = require('express');
const path = require('path');
const fs = require('fs');
const emails = require('./emails');

// Crash logging — write to persistent disk so we can diagnose Render crashes
const CRASH_LOG = process.env.DATA_DIR ? path.join(process.env.DATA_DIR, 'crash.log') : null;
function logCrash(label, err) {
  const msg = `[${new Date().toISOString()}] ${label}: ${err?.stack || err?.message || err}\n`;
  console.error(msg);
  if (CRASH_LOG) try { fs.appendFileSync(CRASH_LOG, msg); } catch {}
}
process.on('uncaughtException', (err) => { logCrash('UNCAUGHT', err); process.exit(1); });
process.on('unhandledRejection', (err) => { logCrash('UNHANDLED_REJECTION', err); });
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

// Melbourne timezone helpers
function melb(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleString('en-AU', { timeZone: 'Australia/Melbourne' });
}
function melbDate(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleDateString('en-AU', { timeZone: 'Australia/Melbourne' });
}

// Reusable email sender
async function sendMortiEmail(to, subject, html) {
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  if (!smtpUser || !smtpPass) {
    console.log(`[Email] SMTP not configured — skipping email to ${to}: ${subject}`);
    return false;
  }
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: false,
      auth: { user: smtpUser, pass: smtpPass }
    });
    await transporter.sendMail({
      from: `"Morti Projects" <${smtpUser}>`,
      to, subject, html
    });
    console.log(`[Email] Sent to ${to}: ${subject}`);
    return true;
  } catch (err) {
    console.error(`[Email] Failed to send to ${to}:`, err.message);
    return false;
  }
}

// Import database and authentication
const db = require('./database-adapter');
const auth = require('./auth');
const Hashids = require('hashids');
const hashids = new Hashids('morti-projects-2026', 8);
function encodeProjectId(id) { return hashids.encode(Number(id)); }
function resolveProjectId(val) {
  if (!val) return val;
  if (/^\d+$/.test(val)) return val;
  const decoded = hashids.decode(val);
  return decoded.length ? decoded[0].toString() : val;
}

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

// Capture raw body for Stripe webhook verification
app.use('/api/billing/stripe-webhook', express.raw({ type: 'application/json' }));

// Middleware
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logging — write last N requests to ring buffer, dump on crash
const REQUEST_LOG_SIZE = 20;
const recentRequests = [];
app.use((req, res, next) => {
  const entry = `${new Date().toISOString()} ${req.method} ${req.url} IP:${req.ip} UA:${(req.headers['user-agent']||'').slice(0,80)} Cookies:${Object.keys(req.cookies||{}).join(',')}`;
  recentRequests.push(entry);
  if (recentRequests.length > REQUEST_LOG_SIZE) recentRequests.shift();
  next();
});

// On crash, dump recent requests
const origLogCrash = logCrash;
const _logCrash = logCrash;
function logCrashWithRequests(label, err) {
  const reqDump = `\n--- Last ${recentRequests.length} requests ---\n${recentRequests.join('\n')}\n--- End requests ---\n`;
  const msg = `[${new Date().toISOString()}] ${label}: ${err?.stack || err?.message || err}${reqDump}`;
  console.error(msg);
  if (CRASH_LOG) try { fs.appendFileSync(CRASH_LOG, msg); } catch {}
}
// Override the process handlers
process.removeAllListeners('uncaughtException');
process.removeAllListeners('unhandledRejection');
process.on('uncaughtException', (err) => { logCrashWithRequests('UNCAUGHT', err); process.exit(1); });
process.on('unhandledRejection', (err) => { logCrashWithRequests('UNHANDLED_REJECTION', err); });

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
  const message = 'SECURITY ALERT: Morti Projects\nType: ' + type + '\nTime: ' + melb(new Date()) + '\nDetails: ' + JSON.stringify(details);

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

// Make timezone helpers available to all templates
app.use((req, res, next) => {
  res.locals.melb = melb;
  res.locals.melbDate = melbDate;
  res.locals.encodeId = encodeProjectId;
  // renderText: convert plain text design content to safe HTML with formatting
  res.locals.renderText = function(txt) {
    if (!txt) return '';
    let s = String(txt).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    s = s.replace(/\[ASSUMPTION\]/g,'<span style="background:rgba(245,158,11,0.15);padding:1px 6px;border-radius:3px;font-size:12px;font-weight:600;color:#f59e0b;">ASSUMPTION</span>');
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    const lines = s.split('\n');
    let html = '', inOl = false, inUl = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) {
        if (inUl) { html += '</ul>'; inUl = false; }
        if (!inOl) html += '<div style="height:8px"></div>';
        continue;
      }
      const numbered = line.match(/^(\d+)\.\s+(.+)/);
      const bullet = line.match(/^[-•]\s+(.+)/);
      if (numbered) {
        if (inUl) { html += '</ul>'; inUl = false; }
        if (!inOl) { html += '<ol style="margin:8px 0;padding:0;list-style:none;">'; inOl = true; }
        html += '<li style="margin-bottom:10px;padding:10px 14px;background:rgba(15,29,50,0.6);border:1px solid rgba(255,255,255,0.08);border-radius:8px;list-style:none;color:rgba(240,244,248,0.7);"><span style="display:inline-block;background:linear-gradient(135deg,#1199fa,#8b5cf6);color:#fff;border-radius:50%;width:24px;height:24px;text-align:center;line-height:24px;font-size:12px;font-weight:700;margin-right:10px;">' + numbered[1] + '</span>' + numbered[2] + '</li>';
      } else if (bullet) {
        if (inOl) { html += '</ol>'; inOl = false; }
        if (!inUl) { html += '<ul style="margin:4px 0 4px 16px;padding:0;">'; inUl = true; }
        html += '<li style="margin-bottom:3px;font-size:13px;color:rgba(240,244,248,0.7);">' + bullet[1] + '</li>';
      } else {
        if (inUl) { html += '</ul>'; inUl = false; }
        if (inOl) { html += '</ol>'; inOl = false; }
        html += '<p style="margin:0 0 4px 0;">' + line + '</p>';
      }
    }
    if (inUl) html += '</ul>';
    if (inOl) html += '</ol>';
    return html;
  };
  next();
});

// Decode hashed IDs in route params (backward compatible with numeric IDs)
app.param('id', (req, res, next, val) => {
  req.params.id = resolveProjectId(val);
  next();
});

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
    let file;
    if (db.queryOne) {
      file = await db.queryOne('SELECT f.*, p.user_id FROM files f JOIN projects p ON f.project_id = p.id WHERE f.filename = $1 OR f.original_name = $2', [filename, filename]);
    }
    if (!file) return res.status(403).send('Forbidden');
    if (file.user_id !== user.id) {
      // Check if user has shared access
      const share = await db.getShareByProjectAndUser(file.project_id, user.id);
      if (!share) return res.status(403).send('Forbidden');
    }
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
    // Get user details before approving (for email)
    const user = await db.getUserById(req.params.id);
    await db.approveUser(req.params.id);

    // Send approval email
    if (user && user.email) {
      const approved = emails.accountApprovedEmail(user.name);
      sendMortiEmail(user.email, approved.subject, approved.html).catch(() => {});
    }

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
    await db.createFeatureRequest(req.user.id, req.user.name, req.user.email, text.trim(), page || 'unknown');
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
    const requests = await db.getAllFeatureRequests();
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

// === ARCHIVED PROJECTS (admin) ===
app.get('/admin/projects/archived', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const projects = await db.getAllArchivedProjects();
  res.render('admin/projects-archived', {
    user: req.user,
    projects,
    title: 'Archived Projects',
    currentPage: 'admin-projects'
  });
});

// Mark project as complete (customer action from voice session)
app.post('/api/projects/:id/complete', apiAuth, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    // Verify ownership (admin or owner)
    if (req.user.role !== 'admin' && project.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    // Update project status to completed and set design_review_requested
    await db.updateProject(projectId, project.name, project.description, 'completed');
    // Set design_review_requested timestamp (uses a simple column add if not exists)
    try {
      await db.pool.query('UPDATE projects SET design_review_requested = NOW() WHERE id = $1', [projectId]);
    } catch (e) {
      // Column might not exist yet — add it
      try {
        await db.pool.query('ALTER TABLE projects ADD COLUMN IF NOT EXISTS design_review_requested TIMESTAMP');
        await db.pool.query('UPDATE projects SET design_review_requested = NOW() WHERE id = $1', [projectId]);
      } catch (e2) { console.warn('Could not set design_review_requested:', e2.message); }
    }
    await db.logAction(req.user.id, 'project_completed', { projectId, projectName: project.name }, req.ip);
    // Notify admin via Telegram
    const tgToken = process.env.TELEGRAM_BOT_TOKEN;
    const tgChat = process.env.TELEGRAM_CHAT_ID;
    if (tgToken && tgChat) {
      const msg = `✅ Project Completed & Ready for Design Review\nProject: ${project.name}\nBy: ${req.user.name} (${req.user.email})\nTime: ${new Date().toLocaleString('en-AU', { timeZone: 'Australia/Melbourne' })}`;
      fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: tgChat, text: msg })
      }).catch(err => console.error('Telegram notify failed:', err.message));
    }
    res.json({ success: true });
  } catch (e) {
    console.error('Complete project error:', e);
    res.status(500).json({ error: 'Failed to complete project' });
  }
});

// Archive/Unarchive project (admin)
app.post('/admin/projects/:id/archive', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    await db.updateProject(req.params.id, project.name, project.description, 'archived');
    res.redirect('/admin/projects?message=Project+archived');
  } catch (e) {
    console.error('Archive error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}?error=Archive+failed`);
  }
});

app.post('/admin/projects/:id/unarchive', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    await db.updateProject(req.params.id, project.name, project.description, 'active');
    res.redirect('/admin/projects/archived?message=Project+unarchived');
  } catch (e) {
    console.error('Unarchive error:', e);
    res.redirect('/admin/projects/archived?error=Unarchive+failed');
  }
});

// Requirements page (admin)
app.get('/admin/projects/:id/requirements', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).send('Project not found');
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
    res.render('admin/project-requirements', { user: req.user, project, requirements: allRequirements, title: project.name + ' - Requirements', currentPage: 'admin-projects' });
  } catch (e) {
    console.error('Requirements error:', e);
    res.status(500).send('Failed to load requirements');
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

  // Compute design/proposal status for milestone tracker
  let hasDesignPublished = false, hasDesignApproved = false;
  let hasProposalPublished = false, hasProposalApproved = false;
  try {
    const designResult = loadNewestDesign(req.params.id);
    if (designResult && designResult.design) {
      hasDesignPublished = !!designResult.design.published;
      hasDesignApproved = !!designResult.design.approvedAt;
    }
  } catch {}
  try {
    const prop = loadNewestProposal(req.params.id);
    if (prop) {
      hasProposalPublished = !!prop.published;
      hasProposalApproved = !!prop.approvedAt;
    }
  } catch {}
  const hasReqs = sessions.some(s => {
    try { const r = JSON.parse(s.requirements || '{}'); return Object.values(r).some(a => Array.isArray(a) && a.length > 0); } catch { return false; }
  });

  res.render('admin/project-detail', {
    customerAnswers,
    designExists: designExists,
    hasDesignPublished,
    hasDesignApproved,
    hasProposalPublished,
    hasProposalApproved,
    hasReqs,
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


// === ADMIN SESSION MANAGEMENT ===

// List all sessions across all projects
app.get('/admin/sessions', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const sessions = await db.getAllSessions();
  // Parse transcript to get message count
  const enriched = sessions.map(s => {
    let messageCount = 0;
    try { messageCount = JSON.parse(s.transcript || '[]').length; } catch {}
    return { ...s, message_count: messageCount };
  });
  res.render('admin/sessions', {
    user: req.user,
    sessions: enriched,
    title: 'All Sessions',
    currentPage: 'admin-sessions',
    query: req.query
  });
});

// Admin: view/access project session (same UI as customer)
app.get('/admin/projects/:id/session', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');

  // Check for existing active session
  let activeSession = await db.getLatestSessionForProject(req.params.id);
  if (!activeSession || activeSession.status === 'completed') {
    // Create new session
    const result = await db.createSession(req.params.id);
    activeSession = { id: result.lastInsertRowid };
  }

  res.redirect(`/voice-session?project=${encodeProjectId(req.params.id)}&session=${activeSession.id}`);
});

// Admin: create a new session for a project
app.post('/admin/projects/:id/session/create', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const project = await db.getProject(req.params.id);
  if (!project) return res.status(404).send('Project not found');
  const result = await db.createSession(req.params.id);
  res.redirect(`/voice-session?project=${encodeProjectId(req.params.id)}&session=${result.lastInsertRowid}`);
});

// Admin: view session transcript (standalone page)
app.get('/admin/sessions/:id/view', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const session = await db.getSession(req.params.id);
  if (!session) return res.status(404).send('Session not found');
  const project = await db.getProject(session.project_id);
  let transcript = [];
  let requirements = {};
  try { transcript = JSON.parse(session.transcript || '[]'); } catch {}
  try { requirements = JSON.parse(session.requirements || '{}'); } catch {}
  res.render('admin/session-view', {
    user: req.user,
    session,
    project,
    transcript,
    requirements,
    title: `Session #${session.id} - ${project ? project.name : 'Unknown'}`,
    currentPage: 'admin-sessions'
  });
});

// Morti Projects: Design extraction and admin design view
app.post('/admin/projects/:id/extract-design', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const projectId = req.params.id;
  
  // Mark as generating and redirect immediately
  generationStatus[projectId] = { type: 'design', status: 'generating', startedAt: Date.now() };
  res.redirect(`/admin/projects/${encodeProjectId(projectId)}/design`);
  
  // Run extraction in background
  extractDesignAsync(projectId, req.user).catch(err => {
    console.error('Background design extraction failed:', err);
    generationStatus[projectId] = { type: 'design', status: 'error', error: err.message };
  });
});

async function extractDesignAsync(projectId, user) {
  try {
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
    for (const f of files) {
      let text = '';
      // Read full file from disk (not truncated DB text)
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
        // Cap at 50K per file for context window safety
        if (text.length > 50000) text = text.substring(0, 50000) + '\n\n[...truncated from ' + text.length + ' chars]';
        reqText += `\n\nUPLOADED FILE: ${fname}\n${f.description ? 'Description: ' + f.description + '\n' : ''}Content:\n${text}\n`;
      } else {
        reqText += `\nUPLOADED FILE: ${fname} (no text extracted)\n`;
      }
    }

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
    let designParsedCustomerDesign = null;
    let designParsedEngineDesign = null;
    let designSummary = '';

    const DESIGN_SECTIONS_SCHEMA = `{
  "summary": "3-5 sentence executive summary: what this system actually is, the core operating loop, what problem it solves, and what it is NOT.",
  "customerDesign": {
    "ExecutiveSummary": "Plain English explanation of what this system is. What problem it solves, for whom, and the core value proposition. 2-4 paragraphs max. Write for a business stakeholder, not an engineer.",
    "HowItWorks": "Step-by-step operational flow from the USER'S perspective as a NUMBERED LIST. Each step: a short bold title, then 1-2 sentences describing what happens. Focus on what the user sees/does, not internal plumbing. Keep it to 4-8 steps max. Example format: 1. **Submit Request** — You upload your brief and the system extracts key requirements automatically.",
    "WhatYouGet": "Concrete deliverables and outcomes as a BULLETED LIST. What the customer will actually receive — screens, dashboards, automations, reports, integrations. Be specific and tangible. Include any key metrics or KPIs the system will track.",
    "WhatWeNeedFromYou": "BULLETED LIST of everything needed from the customer to proceed: access credentials, decisions to make, content to provide, approvals needed, stakeholder availability. Tag each as (Before Build), (During Build), or (Before Launch).",
    "TimelineAndInvestment": "Phases with timeline and what gets delivered in each phase. Include complexity rating (Low/Medium/High) and rough effort estimate. Be practical and specific. If cost data was not provided, note this clearly.",
    "AutomatedVsManual": "TWO LISTS: 'The System Handles' and 'You Still Control'. For each item: what it is and why it's in that category. Focus on the strategic value of what stays human (decisions, approvals, quality control) vs what gets automated (repetition, data entry, notifications)."
  },
  "engineDesign": {
    "TechnicalArchitecture": "Architecture as a BULLETED LIST of components. For each: component name, specific tool/service recommended, rationale, and how it connects to other components. Include hosting, deployment, and a 'NOT required for MVP' list. Avoid microservices and enterprise over-engineering.",
    "DataModel": "BULLETED LIST of entities. For each: **Entity Name** — all key fields with types/descriptions, relationships to other entities, purpose in the system. Include example values where helpful.",
    "IntegrationsAndAPIs": "COMPREHENSIVE list of all external services, APIs, webhooks needed. For each: service name, what it's used for, endpoint/auth details if known, cost tier, and tag as (Critical) or (Optional). Include: APIs & Endpoints (URLs, methods, auth, request/response formats, rate limits), Integration Specifics (webhook formats, callback URLs, polling intervals), Configuration (env vars, feature flags). Quote directly from source material where possible.",
    "BuildSpecification": "DETAILED step-by-step build specification as a NUMBERED LIST. This is the engineering team's primary reference. For EACH step include: (a) **Bold step name**, (b) Detailed description — inputs, processing, outputs, (c) Data flow — what comes in and goes out, (d) Error handling — what happens if this step fails, (e) Specific tools/services used, (f) Business rules, conditions, and logic that apply, (g) Human control/review points if applicable. There is NO length limit — be exhaustive. Also include: assumptions made (mark with [ASSUMPTION]), dependencies between steps, and any technical details extracted from requirements (field names, data types, regex patterns, code snippets, URLs, compliance requirements).",
    "RiskRegister": "BULLETED LIST of realistic risks. For each: **Risk** — likelihood, impact, detailed mitigation strategy, and who is responsible. Include technical risks, dependency risks, and timeline risks. No theatrical or enterprise-only risks."
  },
  "assets": [
    {"id": "asset-1", "name": "Descriptive name", "type": "google-sheet | google-script | web-app | static-page | google-doc", "purpose": "What this asset is for and how it connects to the automation", "buildNotes": "Specific instructions for building — columns/structure for sheets, functionality for apps, content for docs", "linkedToSteps": [0, 1]}
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
- The Morti Engine builds automations using **Pipedream Connect** (primary) or **n8n** (self-hosted, for complex cases) as the orchestration layer.
- **Pipedream Connect** (preferred): Managed auth via OAuth — customer connects their accounts (Google, OpenAI, Slack, etc.) and the engine invokes actions on their behalf. 2700+ app integrations. No credential sharing needed.
- Pipedream workflows are deployed as step-by-step pipelines. Each step is deployed, tested with real data, and advanced individually.
- **n8n** (alternative): Self-hosted on Railway for complex workflows needing custom code, self-hosted data, or integrations not on Pipedream. n8n Code nodes do NOT have fetch/require/import — HTTP calls must use HTTP Request node.
- For each automation workflow, the engineDesign.BuildSpecification should describe steps as a pipeline: inputs, processing, outputs, and which app/API each step uses.
- The TechnicalArchitecture section should specify: (a) primarily a Pipedream automation pipeline, (b) a web app with Pipedream automations supporting it, (c) an n8n workflow (self-hosted needs), or (d) a custom build.
- Each customer gets isolated multi-tenant deployment via Pipedream external_user_id.

ASSETS — REQUIRED RESOURCES:
- Identify any assets that need to exist BEFORE or ALONGSIDE the automation pipeline. These are NOT automation steps — they are resources the automation depends on.
- Asset types: google-sheet (tracking/data storage), google-script (Apps Script custom logic/web apps), web-app (frontend input pages, dashboards), static-page (landing pages, confirmation pages), google-doc (templates, documents).
- For each asset, specify: a clear name, the type, what it's for (purpose), specific build instructions (buildNotes — e.g. column names for sheets, page functionality for web apps), and which pipeline steps use it (linkedToSteps by step number).
- Examples of assets: "A Google Sheet to track blog draft status and approvals", "A simple voice input web page for capturing ideas", "A Google Doc template for client proposals".
- If the project mentions spreadsheets, forms, dashboards, tracking, input pages, or templates — these are assets, not automation steps.
- The customer will choose whether to provide an existing asset or have the engine build it.

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
        // REFRESH: update existing design with new information only
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
      // On refresh, focus on new information — PRIORITY ORDER matters
      const newInfo = [];

      // HIGHEST PRIORITY: Design chat feedback — admin explicitly requested changes
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

      // Admin notes
      try {
        const adminNotes = JSON.parse(project.admin_notes || '[]');
        if (adminNotes.length > 0) {
          newInfo.push('ADMIN NOTES (incorporate these):\n' + adminNotes.map(n => `- ${n.text}`).join('\n'));
        }
      } catch(e) {}

      if (prevAnswersText) newInfo.push('ANSWERED QUESTIONS:\n' + prevAnswersText);
      
      // Include accepted assumptions
      if (previousDesign.acceptedAssumptions && previousDesign.acceptedAssumptions.length > 0) {
        newInfo.push('ACCEPTED ASSUMPTIONS (incorporate these as decisions, do NOT re-ask):\n' + 
          previousDesign.acceptedAssumptions.map(a => `- Q: ${a.question} → Assumption accepted: ${a.assumption}`).join('\n'));
      }
      
      // Include full transcript for context but mark it as lower priority
      newInfo.push('FULL PROJECT TRANSCRIPT (background reference only — chat feedback above takes priority over anything here):\n' + reqText.substring(0, 40000));
      
      promptContext = newInfo.join('\n\n---\n\n');
    }

    if (OPENAI_KEY) {
      try {
        const prompt = buildPrompt(promptContext, prevAnswersText, previousDesign);
        const model = process.env.LLM_MODEL || process.env.OPENAI_MODEL || 'gpt-4.1';
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
          body: JSON.stringify({ model: model, max_completion_tokens: 16000, messages: [{ role: 'system', content: 'You are a senior solutions architect and business analyst. You produce detailed, actionable solution designs. The CoreWorkflow section should be your most detailed section — expand fully with no length limit.' }, { role: 'user', content: prompt }] })
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
            
            // Helper to flatten nested objects to text
            const flattenObj = (obj, prefix = '') => {
              let out = '';
              if (Array.isArray(obj)) {
                obj.forEach((item, i) => {
                  if (typeof item === 'object') out += flattenObj(item, `${i+1}. `);
                  else out += `- ${item}\n`;
                });
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

            // Handle new split format (customerDesign + engineDesign)
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

            // Also support old format (parsed.design) for backward compat
            if (parsed.design && typeof parsed.design === 'object' && !parsedCustomerDesign) {
              const flatDesign = {};
              for (const [key, val] of Object.entries(parsed.design)) {
                flatDesign[key] = flattenSection(val);
              }
              designParsedSections = flatDesign;
            } else if (typeof parsed.design === 'string' && !parsedCustomerDesign) {
              llmDesignMarkdown = parsed.design;
            }

            // Build combined sections for backward compat (merge customer + engine)
            if (parsedCustomerDesign || parsedEngineDesign) {
              designParsedSections = { ...(parsedCustomerDesign || {}), ...(parsedEngineDesign || {}) };
            }

            // Convert to markdown for designMarkdown field
            if (designParsedSections) {
              let md = '';
              for (const [section, body] of Object.entries(designParsedSections)) {
                const title = section.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase()).trim();
                md += `## ${title}\n\n${body}\n\n`;
              }
              llmDesignMarkdown = md;
            }
            
            if (parsed.summary) {
              designSummary = parsed.summary;
            }
            
            if (parsed.questions && Array.isArray(parsed.questions)) {
              llmQuestions = parsed.questions;
            }
            
            // Store split designs for later use
            if (parsedCustomerDesign) designParsedCustomerDesign = parsedCustomerDesign;
            if (parsedEngineDesign) designParsedEngineDesign = parsedEngineDesign;
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
      owner: user.email,
      version: designVersion,
      status: designStatus,
      summary: designSummary,
      designMarkdown: llmDesignMarkdown,
      designHtml: mdToHtml(llmDesignMarkdown),
      sections: designParsedSections,
      customerDesign: designParsedCustomerDesign,
      engineDesign: designParsedEngineDesign,
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
        if (prev.coreWorkflowFlowchart) design.coreWorkflowFlowchart = prev.coreWorkflowFlowchart;
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

    generationStatus[projectId] = { type: 'design', status: 'done', finishedAt: Date.now() };
    console.log(`✅ Design extracted for project ${projectId}`);
  } catch (e) {
    console.error('Extract design error:', e);
    generationStatus[projectId] = { type: 'design', status: 'error', error: e.message };
  }
}

app.get('/admin/projects/:id/design', auth.authenticate, auth.requireAdmin, async (req, res) => {
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
    // Check if engine build still exists — revert button if deleted
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
              // Build was deleted in Engine — clear build refs but keep sent status
              delete design.enginePlanId;
              delete design.engineBuildId;
              saveDesign(design);
            }
          }
        }
      } catch (e) { /* Engine unreachable — leave as-is */ }
    }

    res.render('admin/project-design', { user: req.user, projectId, projectName, design, generating: isGenerating, title: projectName + ' - Design' });
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

// Sanitise mermaid syntax from LLM output
function sanitiseMermaid(raw) {
  let code = (raw || '').trim();
  // Strip markdown code fences
  code = code.replace(/^```(?:mermaid)?\s*/im, '').replace(/```\s*$/m, '').trim();
  // Ensure header exists
  if (!/^(flowchart|graph)\s+(TD|TB|LR|RL|BT)/i.test(code)) {
    code = 'flowchart LR\n' + code;
  }
  // Fix single-dash arrows: -> to -->  (but not already -->)
  code = code.replace(/([^\-])->/g, '$1-->');
  // Fix lines — sanitise node labels containing special chars
  const lines = code.split('\n');
  const sanitised = lines.map(line => {
    // Match node definitions: ID[Label], ID(Label), ID{Label}, ID([Label]), ID[[Label]], ID[(Label)]
    return line.replace(/(\b\w+)((?:\[\[|\[\(|\(\[|\[|\(\(|\(|\{))(.*?)((?:\]\]|\)\]|\]\)|\]\)|\)|\}|\]))(?=\s|$|;)/g, (match, id, open, label, close) => {
      // Strip existing quotes to re-wrap cleanly
      let clean = label.replace(/^["']|["']$/g, '').trim();
      // Always wrap in quotes for safety
      clean = '"' + clean.replace(/"/g, "'") + '"';
      return id + open + clean + close;
    });
  });
  code = sanitised.join('\n');
  // Remove empty lines that could cause parse issues
  code = code.replace(/\n{3,}/g, '\n\n');
  return code;
}

// Basic mermaid syntax validation
function isMermaidValid(code) {
  if (!code) return false;
  if (!/^(flowchart|graph)\s+(TD|TB|LR|RL|BT)/i.test(code)) return false;
  const lines = code.split('\n').filter(l => l.trim() && !l.trim().startsWith('%%'));
  if (lines.length < 3) return false;
  // Check for at least one arrow
  if (!(/-->/.test(code))) return false;
  // Check for balanced brackets
  const opens = (code.match(/\[/g) || []).length;
  const closes = (code.match(/\]/g) || []).length;
  if (Math.abs(opens - closes) > 1) return false;
  return true;
}

// Generate mermaid flowchart via OpenAI
app.post('/admin/projects/:id/design/flowchart', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const result = loadNewestDesign(req.params.id);
    if (!result) return res.status(404).json({ error: 'No design found' });
    const { design } = result;

    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (!OPENAI_KEY) return res.status(500).json({ error: 'OpenAI API key not configured' });

    // Build context from sections (support both old and new format)
    const sections = design.sections || {};
    const designContext = JSON.stringify({ summary: design.summary, customerDesign: design.customerDesign, engineDesign: design.engineDesign, sections }, null, 2);

    const prompt = `You are a systems architect creating a HIGH-LEVEL COMPONENT DIAGRAM as a Mermaid flowchart.

STRICT MERMAID SYNTAX RULES — follow these exactly:
1. First line MUST be: flowchart LR
2. EVERY node label MUST be wrapped in double quotes: A["My Label"]
3. Arrows MUST use -->  (two dashes + angle bracket). For labeled arrows: A -->|"label"| B
4. Node shapes: ["Rectangle"], (["Stadium"]), [("Cylinder/DB")], {{"Hexagon"}}
5. Subgraphs: subgraph Title\\n ... end
6. Node IDs must be simple alphanumeric: A, B, C1, DB1 — no spaces or special chars in IDs
7. NO semicolons at end of lines
8. NO markdown fences — return raw mermaid code only

VALID EXAMPLE:
flowchart LR
  subgraph Core["Our System"]
    A["Web App"]
    B["API Server"]
    C[("PostgreSQL")]
    A -->|"REST"| B
    B -->|"queries"| C
  end
  subgraph Ext["External Services"]
    D["Stripe API"]
    E["SendGrid"]
  end
  B -->|"payments"| D
  B -->|"emails"| E

INVALID (do NOT do these):
- A[My Label]  ← missing quotes around label
- A -> B  ← wrong arrow, must be -->
- \`\`\`mermaid  ← no code fences

Rules for content:
- Show ONLY system components and their connections (not user journeys)
- 8-15 nodes maximum
- Group into subgraphs: "Our System" and "External Services"
- Node shapes: ["Component"] for services, [("Database")] for data stores

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
            { role: 'system', content: 'You generate valid Mermaid flowchart syntax. Return ONLY raw mermaid code. No markdown, no explanation. Every node label must be in double quotes.' },
            { role: 'user', content: prompt + extraContext }
          ]
        })
      });
      if (!resp.ok) throw new Error('OpenAI API returned ' + resp.status);
      const data = await resp.json();
      return (data.choices[0].message.content || '').trim();
    };

    // First attempt
    let raw = await generateFlowchart();
    let mermaid = sanitiseMermaid(raw);

    // Retry once if validation fails
    if (!isMermaidValid(mermaid)) {
      console.warn('Flowchart first attempt failed validation, retrying...');
      const retryContext = `\n\nPREVIOUS ATTEMPT WAS INVALID. The output had syntax errors. Common issues: missing quotes around labels, wrong arrow syntax, or missing flowchart header. Please try again following the syntax rules exactly. Here was the broken output for reference:\n${raw.substring(0, 1000)}`;
      raw = await generateFlowchart(retryContext);
      mermaid = sanitiseMermaid(raw);
    }

    // Save flowchart to design JSON
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
    res.redirect(`/admin/projects/${encodeProjectId(projectId)}?message=Answer+saved`);
  } catch (e) {
    console.error('Design answer error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/design?error=Save+failed`);
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

    // Send design-ready email to project owner
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

// Admin notes for project
app.post('/admin/projects/:id/notes', auth.authenticate, auth.requireAdmin, async (req, res) => {
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

app.post('/admin/projects/:id/notes/:noteIndex/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
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

app.post('/admin/projects/:id/design/unpublish', auth.authenticate, auth.requireAdmin, async (req, res) => {
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
app.post('/admin/projects/:id/design/:designId/delete', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const filePath = path.join(DESIGNS_DIR, req.params.designId + '.json');
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}?message=Design+deleted`);
  } catch (e) {
    console.error('Delete design error:', e);
    res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}?error=Delete+failed`);
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
    // Check access: owner or shared with readonly+
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

// === PROPOSAL SYSTEM ===
const PROPOSALS_DIR = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'proposals');
if (!fs.existsSync(PROPOSALS_DIR)) fs.mkdirSync(PROPOSALS_DIR, { recursive: true });

// In-memory generation status tracking
const generationStatus = {}; // { [projectId]: { type: 'proposal'|'design', status: 'generating'|'done'|'error', error?: string, startedAt: number } }

const loadNewestProposal = (projectId) => {
  const files = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${projectId}-`)).sort().reverse();
  if (files.length === 0) return null;
  return JSON.parse(fs.readFileSync(path.join(PROPOSALS_DIR, files[0]), 'utf8'));
};

// Poll generation status
app.get('/admin/projects/:id/generation-status', auth.authenticate, auth.requireAdmin, (req, res) => {
  const status = generationStatus[req.params.id];
  if (!status) return res.json({ status: 'idle' });
  res.json(status);
});

// View proposal
app.get('/admin/projects/:id/proposal', auth.authenticate, auth.requireAdmin, async (req, res) => {
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
app.post('/admin/projects/:id/generate-proposal', auth.authenticate, auth.requireAdmin, async (req, res) => {
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
app.post('/admin/projects/:id/proposal/chat', auth.authenticate, auth.requireAdmin, async (req, res) => {
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

// Publish/unpublish proposal
app.post('/admin/projects/:id/proposal/publish', auth.authenticate, auth.requireAdmin, (req, res) => {
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

app.post('/admin/projects/:id/proposal/unpublish', auth.authenticate, auth.requireAdmin, (req, res) => {
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
app.post('/admin/projects/:id/proposal/delete', auth.authenticate, auth.requireAdmin, (req, res) => {
  const files = fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${req.params.id}-`));
  files.forEach(f => fs.unlinkSync(path.join(PROPOSALS_DIR, f)));
  res.redirect(`/admin/projects/${encodeProjectId(req.params.id)}/proposal`);
});

// Customer: view published proposal
app.get('/customer/projects/:id/proposal', auth.authenticate, async (req, res) => {
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
app.post('/customer/projects/:id/proposal/approve', auth.authenticate, async (req, res) => {
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

// ─── Customer Onboarding (proxied to Morti Engine) ─────────

// Helper to get engine build ID from project's design
function getEngineBuildId(projectId) {
  const result = loadNewestDesign(projectId);
  if (!result || !result.design) return null;
  return result.design.engineBuildId || null;
}

// Customer onboarding page
app.get('/customer/projects/:id/onboarding', auth.authenticate, async (req, res) => {
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
app.post('/customer/projects/:id/onboarding', auth.authenticate, async (req, res) => {
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
    console.log(`✅ Proposal generated for project ${projectId}`);
  } catch(e) {
    console.error('Proposal generation error:', e);
    generationStatus[projectId] = { type: 'proposal', status: 'error', error: e.message };
  }
}

// Customer: approve design
app.post('/customer/projects/:id/design/approve', auth.authenticate, async (req, res) => {
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

// ─── Send to Morti Engine ──────────────────────────────────
// NOTE: In production, ENGINE_API_URL should use HTTPS
app.post('/admin/projects/:id/send-to-engine', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = await db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const result = loadNewestDesign(projectId);
    if (!result || !result.design) return res.status(400).json({ error: 'No design found for this project' });
    if (!result.design.approvedAt) return res.status(400).json({ error: 'Design must be approved before sending to engine' });

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

// Customer: archive/unarchive project
// === PROJECT SHARING ROUTES ===
const crypto = require('crypto');

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

// Email validation helper
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Send invite email (graceful without SMTP)
const sendInviteEmail = async (to, inviterName, projectName, permission, signupLink, projectLink) => {
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  if (!smtpUser || !smtpPass) {
    console.log(`[Invite] SMTP not configured. Invite for ${to} to "${projectName}" logged.`);
    return { sent: false, reason: 'SMTP not configured' };
  }
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: smtpUser, pass: smtpPass }
    });
    await transporter.sendMail({
      from: `"Morti Projects" <${smtpUser}>`,
      to,
      subject: `You've been invited to a project on Morti Projects`,
      text: `Hi,\n\n${inviterName} has shared the project "${projectName}" with you on Morti Projects.\n\nYour access level: ${permission}\n\nClick here to view the project: ${projectLink}\n\nIf you don't have an account yet, sign up here: ${signupLink}\n\nMorti Projects — AI-Powered Project Management`
    });
    return { sent: true };
  } catch (e) {
    console.error('Send invite email failed:', e.message);
    return { sent: false, reason: e.message };
  }
};

// Share a project (admin route)
app.post('/admin/projects/:id/share', auth.authenticate, auth.requireAdmin, async (req, res) => {
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
app.get('/admin/projects/:id/shares', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const shares = await db.getProjectShares(req.params.id);
  res.json({ shares });
});

// Update share permission (admin)
app.put('/admin/projects/:id/share/:shareId', auth.authenticate, auth.requireAdmin, async (req, res) => {
  const { permission } = req.body;
  if (!['admin', 'user', 'readonly'].includes(permission)) return res.status(400).json({ error: 'Invalid permission' });
  await db.updateSharePermission(req.params.shareId, permission);
  res.json({ success: true });
});

// Remove share (admin)
app.delete('/admin/projects/:id/share/:shareId', auth.authenticate, auth.requireAdmin, async (req, res) => {
  await db.removeShare(req.params.shareId);
  res.json({ success: true });
});

// Share a project (customer route - must be owner or admin collaborator)
app.post('/customer/projects/:id/share', auth.authenticate, async (req, res) => {
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
app.get('/customer/projects/:id/shares', auth.authenticate, async (req, res) => {
  const project = await canManageShares(req, res);
  if (!project) return;
  const shares = await db.getProjectShares(req.params.id);
  res.json({ shares });
});

// Update share permission (customer)
app.put('/customer/projects/:id/share/:shareId', auth.authenticate, async (req, res) => {
  const project = await canManageShares(req, res);
  if (!project) return;
  const { permission } = req.body;
  if (!['admin', 'user', 'readonly'].includes(permission)) return res.status(400).json({ error: 'Invalid permission' });
  await db.updateSharePermission(req.params.shareId, permission);
  res.json({ success: true });
});

// Remove share (customer)
app.delete('/customer/projects/:id/share/:shareId', auth.authenticate, async (req, res) => {
  const project = await canManageShares(req, res);
  if (!project) return;
  await db.removeShare(req.params.shareId);
  res.json({ success: true });
});

app.post('/customer/projects/:id/archive', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project || project.user_id !== req.user.id) return res.status(403).send('Forbidden');
    await db.updateProject(req.params.id, project.name, project.description, 'archived');
    res.redirect('/projects?message=Project+archived');
  } catch (e) {
    res.redirect(`/projects/${encodeProjectId(req.params.id)}?error=Archive+failed`);
  }
});

app.post('/customer/projects/:id/unarchive', auth.authenticate, auth.requireCustomer, async (req, res) => {
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
app.get('/projects/archived', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const projects = await db.getArchivedProjectsByUser(req.user.id);
  res.render('customer/projects-archived', { user: req.user, projects, title: 'Archived Projects', currentPage: 'customer-projects' });
});

// Customer: requirements page
app.get('/customer/projects/:id/requirements', auth.authenticate, async (req, res) => {
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

    res.redirect(`/projects/${encodeProjectId(projectId)}`);
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

// === MOBILE CUSTOMER ROUTES ===

app.get('/m', auth.authenticate, auth.requireCustomer, async (req, res) => {
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

app.get('/m/projects', auth.authenticate, auth.requireCustomer, async (req, res) => {
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

app.get('/m/projects/:id', auth.authenticate, auth.requireCustomer, async (req, res) => {
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

app.get('/m/projects/:id/design', auth.authenticate, auth.requireCustomer, async (req, res) => {
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

app.get('/m/projects/:id/proposal', auth.authenticate, auth.requireCustomer, async (req, res) => {
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

app.get('/m/projects/:id/voice', auth.authenticate, auth.requireCustomer, async (req, res) => {
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

app.get('/m/profile', auth.authenticate, auth.requireCustomer, async (req, res) => {
  res.render('customer/mobile/profile', { user: req.user });
});

// === CUSTOMER ROUTES ===

app.get('/dashboard', auth.authenticate, auth.requireCustomer, async (req, res) => {
  const projects = await db.getProjectsByUser(req.user.id);
  const fullUser = await db.getUserById(req.user.id);
  const sharedProjects = (fullUser && typeof db.getSharedProjects === 'function') ? await db.getSharedProjects(req.user.id, fullUser.email) : [];
  
  // Enrich projects with stage info
  const enriched = projects.map(p => {
    const designFiles = fs.existsSync(DESIGNS_DIR) ? fs.readdirSync(DESIGNS_DIR).filter(f => f.startsWith(`design-${p.id}-`)).sort().reverse() : [];
    const proposalFiles = fs.existsSync(PROPOSALS_DIR) ? fs.readdirSync(PROPOSALS_DIR).filter(f => f.startsWith(`proposal-${p.id}-`)).sort().reverse() : [];
    let hasDesign = false, hasProposal = false, isApproved = false;
    if (designFiles.length > 0) {
      try { const d = JSON.parse(fs.readFileSync(path.join(DESIGNS_DIR, designFiles[0]), 'utf8')); hasDesign = !!d.published; } catch {}
    }
    if (proposalFiles.length > 0) {
      try { const pr = JSON.parse(fs.readFileSync(path.join(PROPOSALS_DIR, proposalFiles[0]), 'utf8')); hasProposal = !!pr.published; isApproved = !!pr.approvedAt; } catch {}
    }
    const stage = isApproved ? 'approved' : hasProposal ? 'proposal' : hasDesign ? 'design' : (p.session_count > 0 ? 'session' : 'new');
    return { ...p, stage, hasDesign, hasProposal, isApproved };
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
app.get('/projects', auth.authenticate, auth.requireCustomer, (req, res) => {
  const query = req.query.new === 'true' ? '?new=true' : '';
  res.redirect('/dashboard' + query);
});

app.get('/projects/new', auth.authenticate, auth.requireCustomer, (req, res) => {
  res.redirect('/dashboard?new=true');
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

app.get('/projects/:id/session', auth.authenticate, auth.requireCustomer, async (req, res) => {
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
    // Create new session
    const result = await db.createSession(req.params.id);
    activeSession = { id: result.lastInsertRowid };
  }
  
  res.redirect(`/voice-session?project=${encodeProjectId(req.params.id)}&session=${activeSession.id}`);
});

app.get('/voice-session', auth.authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'voice-session.html'));
});

// === API ROUTES ===

// File upload and text extraction endpoint
app.post('/api/upload', optionalAuth, uploadLimiter, upload.single('file'), async (req, res) => {
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

    // Store full content length for reference
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
app.post('/api/analyze', optionalAuth, express.json({ limit: '10mb' }), async (req, res) => {
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
app.post('/api/analyze-session', optionalAuth, express.json({ limit: '20mb' }), async (req, res) => {
  try {
    const { transcript, fileContents, sessionId: rawSessionId, projectId: rawProjectId, existingRequirements } = req.body;
    const projectId = resolveProjectId(rawProjectId);
    const sessionId = resolveProjectId(rawSessionId); // decode hashid to integer if needed
    
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
        
        // Try to read full file from disk first
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
            // Cap at 50K per file to avoid blowing context window (still much better than old 8K truncation)
            if (fullContent) {
              if (fullContent.length > 50000) {
                filesToAnalyze[fname] = fullContent.substring(0, 50000) + '\n\n[...truncated from ' + fullContent.length + ' chars — first 50,000 included]';
              } else {
                filesToAnalyze[fname] = fullContent;
              }
            }
          } catch(e) {
            // Fall back to DB extracted text
            if (file.extracted_text) filesToAnalyze[fname] = file.extracted_text;
          }
        } else if (file.extracted_text) {
          // File not on disk, use DB text
          filesToAnalyze[fname] = file.extracted_text;
        }
      }
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
app.post('/api/chat', optionalAuth, express.json({ limit: '10mb' }), async (req, res) => {
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

// Project info API (for session page to show project name/description)
app.get('/api/projects/:id', apiAuth, async (req, res) => {
  try {
    const project = await db.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Not found' });
    // Only return if user owns the project or is admin
    if (req.user.role !== 'admin' && project.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json({ id: project.id, name: project.name, description: project.description || '', status: project.status });
  } catch(e) {
    res.status(500).json({ error: 'Failed to get project' });
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
    res.redirect('/admin/projects/' + encodeProjectId(projectId));
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

    res.redirect('/admin/projects/' + encodeProjectId(projectId));
  } catch (e) {
    console.error('Project import error:', e);
    res.status(500).send('Import failed: ' + e.message);
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Crash log endpoint — read last crash info from persistent disk
app.get('/api/crash-log', (req, res) => {
  const key = req.query.key;
  if (!key || key !== (process.env.BACKUP_KEY || 'morti-backup-2026')) {
    return res.status(403).json({ error: 'Invalid key' });
  }
  const logPath = process.env.DATA_DIR ? path.join(process.env.DATA_DIR, 'crash.log') : null;
  if (!logPath || !fs.existsSync(logPath)) return res.json({ log: 'No crash log found' });
  const content = fs.readFileSync(logPath, 'utf8');
  // Return last 5000 chars
  res.type('text/plain').send(content.slice(-5000));
});

// Protected backup endpoint — dumps all data as JSON (header-based auth, no session required)
app.get('/api/backup', async (req, res) => {
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
    const signupResult = await db.createPendingUser(email, name, company, phone, hashedPassword);
    
    // Link any pending project shares to this new user
    if (signupResult && signupResult.lastInsertRowid) {
      await db.linkPendingShares(signupResult.lastInsertRowid, email);
    }

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

    // Send welcome email to user
    const welcome = emails.welcomeEmail(name);
    sendMortiEmail(email, welcome.subject, welcome.html).catch(() => {});

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
  const contactTo = process.env.CONTACT_EMAIL || 'info@morti.com.au';

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

// === BILLING ROUTES ===
const billing = require('./billing');

// Email templates for billing
const billingEmailTemplates = {
  receipt: (name, amount, date) => ({
    subject: 'Payment Received — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#1199fa;margin-bottom:20px;">Payment Received ✓</h1>
      <p>Hi ${name},</p>
      <p>We've received your payment of <strong>$${(amount/100).toFixed(2)} AUD</strong> on ${date}.</p>
      <p>Thank you for your continued trust in Morti Projects.</p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  card_expiry: (name, last4, expMonth, expYear) => ({
    subject: 'Card Expiring Soon — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#f59e0b;margin-bottom:20px;">⚠️ Card Expiring Soon</h1>
      <p>Hi ${name},</p>
      <p>Your card ending in <strong>${last4}</strong> expires <strong>${expMonth}/${expYear}</strong>.</p>
      <p>Please update your payment method to avoid service interruption.</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#1199fa;color:#fff;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Update Card</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  payment_failed_1: (name) => ({
    subject: 'Payment Failed — We\'ll Retry — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#f59e0b;margin-bottom:20px;">Payment Failed</h1>
      <p>Hi ${name},</p>
      <p>Your latest payment didn't go through. Don't worry — we'll automatically retry in a few days.</p>
      <p>If you'd like to update your payment method now:</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#1199fa;color:#fff;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Update Card</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  payment_failed_2: (name) => ({
    subject: 'Urgent: Payment Issue — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#ef4444;margin-bottom:20px;">⚠️ Urgent: Payment Issue</h1>
      <p>Hi ${name},</p>
      <p>We've been unable to process your payment after multiple attempts. Please update your payment method immediately to keep your automations running.</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#ef4444;color:#fff;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Update Payment Now</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  payment_failed_final: (name) => ({
    subject: 'Final Warning: Service Pausing in 24hrs — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#ef4444;margin-bottom:20px;">🚨 Final Warning</h1>
      <p>Hi ${name},</p>
      <p>Your payment has failed multiple times. <strong>Your automations will be paused in 24 hours</strong> unless payment is resolved.</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#ef4444;color:#fff;padding:14px 32px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Fix Payment Now</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  automation_paused: (name) => ({
    subject: 'Service Paused — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#ef4444;margin-bottom:20px;">⏸️ Service Paused</h1>
      <p>Hi ${name},</p>
      <p>Due to outstanding payment, your automations have been paused. Update your payment method to restore service immediately.</p>
      <p><a href="${process.env.BASE_URL || 'https://projects.morti.com.au'}/dashboard" style="display:inline-block;background:#1199fa;color:#fff;padding:12px 28px;border-radius:50px;text-decoration:none;font-weight:600;margin-top:16px;">Restore Service</a></p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  }),
  automation_resumed: (name) => ({
    subject: 'Service Restored ✓ — Morti Projects',
    html: `<div style="font-family:Inter,system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0a1628;color:#f0f4f8;padding:40px;border-radius:16px;">
      <h1 style="color:#009e7e;margin-bottom:20px;">✅ Service Restored</h1>
      <p>Hi ${name},</p>
      <p>Your payment has been received and your automations are back up and running. Thank you!</p>
      <p style="color:rgba(240,244,248,0.5);font-size:13px;margin-top:30px;">— The Morti Projects Team</p>
    </div>`
  })
};

// Stripe Webhook Handler
app.post('/api/billing/stripe-webhook', async (req, res) => {
  if (!billing.isEnabled()) return res.status(200).json({ received: true, note: 'Stripe not configured' });
  
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = billing.constructWebhookEvent(req.body, sig);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'invoice.paid': {
        const invoice = event.data.object;
        const subId = invoice.subscription;
        const sub = await db.getSubscriptionByStripeId(subId);
        if (sub) {
          await db.updateSubscriptionStatus(sub.id, 'active');
          await db.createBillingEvent(sub.id, event.id, 'invoice.paid', 'succeeded', invoice.amount_paid, null, 0, event.data.object);
          // Update period
          if (invoice.lines && invoice.lines.data && invoice.lines.data[0]) {
            const line = invoice.lines.data[0];
            await db.updateSubscriptionPeriod(sub.id, new Date(line.period.start * 1000), new Date(line.period.end * 1000));
          }
          // Send receipt
          const user = await db.getUserById(sub.user_id);
          if (user) {
            const tmpl = billingEmailTemplates.receipt(user.name, invoice.amount_paid, new Date().toLocaleDateString('en-AU', { timeZone: 'Australia/Melbourne' }));
            sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
          }
          // If was past_due, resume engine
          if (sub.status === 'past_due' || sub.status === 'paused') {
            const engineUrl = process.env.ENGINE_API_URL;
            const engineSecret = process.env.ENGINE_API_SECRET;
            if (engineUrl && engineSecret) {
              try {
                await fetch(`${engineUrl}/api/billing/resume`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
                  body: JSON.stringify({ userId: sub.user_id, buildIds: sub.build_ids || [] })
                });
              } catch (e) { console.error('Engine resume failed:', e.message); }
            }
            if (user) {
              const tmpl = billingEmailTemplates.automation_resumed(user.name);
              sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
            }
          }
        }
        break;
      }
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const subId = invoice.subscription;
        const sub = await db.getSubscriptionByStripeId(subId);
        if (sub) {
          await db.updateSubscriptionStatus(sub.id, 'past_due');
          const attempt = invoice.attempt_count || 1;
          await db.createBillingEvent(sub.id, event.id, 'invoice.payment_failed', 'failed', invoice.amount_due, invoice.last_finalization_error?.message || 'Payment failed', attempt, event.data.object);
          
          const user = await db.getUserById(sub.user_id);
          if (user) {
            let tmpl;
            if (attempt <= 1) {
              tmpl = billingEmailTemplates.payment_failed_1(user.name);
              await db.createPaymentWarning(sub.id, 'payment_failed_1', user.email);
            } else if (attempt === 2) {
              tmpl = billingEmailTemplates.payment_failed_2(user.name);
              await db.createPaymentWarning(sub.id, 'payment_failed_2', user.email);
            } else {
              tmpl = billingEmailTemplates.payment_failed_final(user.name);
              await db.createPaymentWarning(sub.id, 'payment_failed_final', user.email);
              // Pause engine after final warning
              setTimeout(async () => {
                const engineUrl = process.env.ENGINE_API_URL;
                const engineSecret = process.env.ENGINE_API_SECRET;
                if (engineUrl && engineSecret) {
                  try {
                    await fetch(`${engineUrl}/api/billing/pause`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
                      body: JSON.stringify({ userId: sub.user_id, buildIds: sub.build_ids || [], reason: 'payment_failed' })
                    });
                    await db.updateSubscriptionStatus(sub.id, 'paused');
                    const pauseTmpl = billingEmailTemplates.automation_paused(user.name);
                    sendMortiEmail(user.email, pauseTmpl.subject, pauseTmpl.html).catch(() => {});
                  } catch (e) { console.error('Engine pause failed:', e.message); }
                }
              }, 24 * 60 * 60 * 1000); // 24 hours
            }
            if (tmpl) sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
          }
        }
        break;
      }
      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const sub = await db.getSubscriptionByStripeId(subscription.id);
        if (sub) {
          const statusMap = { active: 'active', past_due: 'past_due', canceled: 'cancelled', paused: 'paused' };
          const newStatus = statusMap[subscription.status] || subscription.status;
          await db.updateSubscriptionStatus(sub.id, newStatus);
          await db.createBillingEvent(sub.id, event.id, 'subscription.updated', newStatus, 0, null, 0, event.data.object);
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const sub = await db.getSubscriptionByStripeId(subscription.id);
        if (sub) {
          await db.updateSubscriptionStatus(sub.id, 'cancelled');
          await db.createBillingEvent(sub.id, event.id, 'subscription.deleted', 'cancelled', 0, null, 0, event.data.object);
        }
        break;
      }
      case 'payment_method.expiring': {
        // Not directly tied to subscription — try to find customer
        const pm = event.data.object;
        if (pm.customer) {
          const subResult = await db.pool.query('SELECT s.*, u.name, u.email FROM subscriptions s JOIN users u ON u.id = s.user_id WHERE s.stripe_customer_id = $1 LIMIT 1', [pm.customer]);
          if (subResult.rows[0]) {
            const row = subResult.rows[0];
            const tmpl = billingEmailTemplates.card_expiry(row.name, pm.card?.last4 || '****', pm.card?.exp_month, pm.card?.exp_year);
            sendMortiEmail(row.email, tmpl.subject, tmpl.html).catch(() => {});
            await db.createPaymentWarning(row.id, 'card_expiry', row.email);
          }
        }
        break;
      }
    }
  } catch (e) {
    console.error('Webhook handler error:', e);
  }

  res.json({ received: true });
});

// Customer billing endpoints
app.get('/api/billing/subscriptions', apiAuth, async (req, res) => {
  try {
    const projectId = resolveProjectId(req.query.projectId);
    let subs;
    if (projectId) {
      const project = await db.getProject(projectId);
      if (!project || (req.user.role !== 'admin' && project.user_id !== req.user.id)) return res.status(403).json({ error: 'Forbidden' });
      subs = await db.getSubscriptionsByProject(projectId);
    } else {
      subs = await db.getSubscriptionsByUser(req.user.id);
    }
    res.json({ subscriptions: subs });
  } catch (e) {
    console.error('Get subscriptions error:', e);
    res.status(500).json({ error: 'Failed to fetch subscriptions' });
  }
});

app.get('/api/billing/history', apiAuth, async (req, res) => {
  try {
    const projectId = resolveProjectId(req.query.projectId);
    let subs;
    if (projectId) {
      const project = await db.getProject(projectId);
      if (!project || (req.user.role !== 'admin' && project.user_id !== req.user.id)) return res.status(403).json({ error: 'Forbidden' });
      subs = await db.getSubscriptionsByProject(projectId);
    } else {
      subs = await db.getSubscriptionsByUser(req.user.id);
    }
    let events = [];
    for (const sub of subs) {
      const subEvents = await db.getBillingEventsBySubscription(sub.id);
      events = events.concat(subEvents.map(e => ({ ...e, plan_name: sub.plan_name, project_name: sub.project_name })));
    }
    events.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json({ events });
  } catch (e) {
    console.error('Get billing history error:', e);
    res.status(500).json({ error: 'Failed to fetch billing history' });
  }
});

app.post('/api/billing/update-card', apiAuth, async (req, res) => {
  try {
    if (!billing.isEnabled()) return res.status(503).json({ error: 'Billing not configured' });
    const subs = await db.getSubscriptionsByUser(req.user.id);
    const activeSub = subs.find(s => s.stripe_customer_id);
    if (!activeSub) return res.status(404).json({ error: 'No active subscription found' });
    const returnUrl = (process.env.BASE_URL || 'https://projects.morti.com.au') + '/billing';
    const session = await billing.createPortalSession(activeSub.stripe_customer_id, returnUrl);
    res.json({ url: session.url });
  } catch (e) {
    console.error('Update card error:', e);
    res.status(500).json({ error: 'Failed to create portal session' });
  }
});

// Admin billing endpoints
app.get('/api/admin/billing/overview', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const overview = await db.getBillingOverview();
    res.json(overview);
  } catch (e) {
    console.error('Billing overview error:', e);
    res.status(500).json({ error: 'Failed to fetch billing overview' });
  }
});

app.get('/api/admin/billing/tenant/:userId', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const subs = await db.getSubscriptionsByUser(parseInt(req.params.userId));
    let events = [];
    for (const sub of subs) {
      const subEvents = await db.getBillingEventsBySubscription(sub.id);
      events = events.concat(subEvents);
    }
    res.json({ subscriptions: subs, events });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch tenant billing' });
  }
});

app.post('/api/admin/billing/activate', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { userId, projectId, planName, monthlyAmount, setupAmount, buildIds } = req.body;
    if (!userId || !monthlyAmount) return res.status(400).json({ error: 'userId and monthlyAmount required' });

    const user = await db.getUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!billing.isEnabled()) {
      // Create local record without Stripe
      const sub = await db.createSubscription(userId, projectId || null, null, `local_${Date.now()}`, planName || 'Morti Automation', monthlyAmount, setupAmount || 0, new Date(), new Date(Date.now() + 30 * 24 * 60 * 60 * 1000));
      if (buildIds) await db.pool.query('UPDATE subscriptions SET build_ids = $1 WHERE id = $2', [JSON.stringify(buildIds), sub.id]);
      return res.json({ subscription: sub, note: 'Created locally — Stripe not configured' });
    }

    // Create Stripe customer
    const customer = await billing.createCustomer({ email: user.email, name: user.name, metadata: { userId: String(userId) } });

    // Create subscription
    const stripeSub = await billing.createSubscription({
      customerId: customer.id,
      priceData: { planName: planName || 'Morti Automation', monthlyAmount },
      setupAmount: setupAmount || 0,
      metadata: { userId: String(userId), projectId: String(projectId || '') }
    });

    const periodStart = stripeSub.current_period_start ? new Date(stripeSub.current_period_start * 1000) : new Date();
    const periodEnd = stripeSub.current_period_end ? new Date(stripeSub.current_period_end * 1000) : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    const sub = await db.createSubscription(userId, projectId || null, customer.id, stripeSub.id, planName || 'Morti Automation', monthlyAmount, setupAmount || 0, periodStart, periodEnd);
    if (buildIds) await db.pool.query('UPDATE subscriptions SET build_ids = $1 WHERE id = $2', [JSON.stringify(buildIds), sub.id]);

    await db.logAction(req.user.id, 'billing_activated', { userId, projectId, monthlyAmount, setupAmount }, req.ip);
    res.json({ subscription: sub, stripeSubscription: stripeSub });
  } catch (e) {
    console.error('Activate billing error:', e);
    res.status(500).json({ error: 'Failed to activate billing: ' + e.message });
  }
});

app.post('/api/admin/billing/pause', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { subscriptionId } = req.body;
    const subResult = await db.pool.query('SELECT * FROM subscriptions WHERE id = $1', [subscriptionId]);
    const sub = subResult.rows[0];
    if (!sub) return res.status(404).json({ error: 'Subscription not found' });

    if (billing.isEnabled() && sub.stripe_subscription_id && !sub.stripe_subscription_id.startsWith('local_')) {
      await billing.pauseSubscription(sub.stripe_subscription_id);
    }
    await db.updateSubscriptionStatus(sub.id, 'paused');

    // Pause engine
    const engineUrl = process.env.ENGINE_API_URL;
    const engineSecret = process.env.ENGINE_API_SECRET;
    if (engineUrl && engineSecret) {
      try {
        await fetch(`${engineUrl}/api/billing/pause`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
          body: JSON.stringify({ userId: sub.user_id, buildIds: sub.build_ids || [], reason: 'admin_pause' })
        });
      } catch (e) { console.error('Engine pause failed:', e.message); }
    }

    const user = await db.getUserById(sub.user_id);
    if (user) {
      const tmpl = billingEmailTemplates.automation_paused(user.name);
      sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
    }

    await db.logAction(req.user.id, 'billing_paused', { subscriptionId }, req.ip);
    res.json({ success: true });
  } catch (e) {
    console.error('Pause billing error:', e);
    res.status(500).json({ error: 'Failed to pause billing' });
  }
});

app.post('/api/admin/billing/resume', apiAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { subscriptionId } = req.body;
    const subResult = await db.pool.query('SELECT * FROM subscriptions WHERE id = $1', [subscriptionId]);
    const sub = subResult.rows[0];
    if (!sub) return res.status(404).json({ error: 'Subscription not found' });

    if (billing.isEnabled() && sub.stripe_subscription_id && !sub.stripe_subscription_id.startsWith('local_')) {
      await billing.resumeSubscription(sub.stripe_subscription_id);
    }
    await db.updateSubscriptionStatus(sub.id, 'active');

    // Resume engine
    const engineUrl = process.env.ENGINE_API_URL;
    const engineSecret = process.env.ENGINE_API_SECRET;
    if (engineUrl && engineSecret) {
      try {
        await fetch(`${engineUrl}/api/billing/resume`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${engineSecret}` },
          body: JSON.stringify({ userId: sub.user_id, buildIds: sub.build_ids || [] })
        });
      } catch (e) { console.error('Engine resume failed:', e.message); }
    }

    const user = await db.getUserById(sub.user_id);
    if (user) {
      const tmpl = billingEmailTemplates.automation_resumed(user.name);
      sendMortiEmail(user.email, tmpl.subject, tmpl.html).catch(() => {});
    }

    await db.logAction(req.user.id, 'billing_resumed', { subscriptionId }, req.ip);
    res.json({ success: true });
  } catch (e) {
    console.error('Resume billing error:', e);
    res.status(500).json({ error: 'Failed to resume billing' });
  }
});

// Admin billing page
app.get('/admin/billing', auth.authenticate, auth.requireAdmin, async (req, res) => {
  try {
    const overview = await db.getBillingOverview();
    const subscriptions = await db.getAllSubscriptions();
    res.render('admin/billing', { user: req.user, overview, subscriptions, currentPage: 'admin-billing', title: 'Billing Overview' });
  } catch (e) {
    console.error('Admin billing page error:', e);
    res.status(500).send('Failed to load billing page');
  }
});

// Customer billing page
app.get('/billing', auth.authenticate, auth.requireCustomer, async (req, res) => {
  try {
    const subscriptions = await db.getSubscriptionsByUser(req.user.id);
    let events = [];
    for (const sub of subscriptions) {
      const subEvents = await db.getBillingEventsBySubscription(sub.id);
      events = events.concat(subEvents.map(e => ({ ...e, plan_name: sub.plan_name, project_name: sub.project_name })));
    }
    events.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.render('customer/billing', { user: req.user, subscriptions, events, currentPage: 'customer-billing', title: 'Billing', billingEnabled: billing.isEnabled() });
  } catch (e) {
    console.error('Customer billing page error:', e);
    res.status(500).send('Failed to load billing page');
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  const info = `[${new Date().toISOString()}] EXPRESS ERROR: ${req.method} ${req.url} | IP: ${req.ip} | UA: ${req.headers['user-agent']?.slice(0,100)} | Cookies: ${Object.keys(req.cookies||{}).join(',')} | Error: ${err?.stack || err?.message || err}\n`;
  console.error(info);
  if (CRASH_LOG) try { fs.appendFileSync(CRASH_LOG, info); } catch {}
  try {
    res.status(500).render('error', { 
      message: 'Internal server error',
      user: req.user || null 
    });
  } catch (renderErr) {
    logCrash('ERROR_RENDER_FAIL', renderErr);
    res.status(500).send('Internal server error');
  }
});

// Wait for database to be ready, then start server
db.ready.then(async () => {
  // One-time project rename migration (remove after deploy)
  try {
    if (db.pool) { // Postgres only
      await db.pool.query("UPDATE projects SET name='Warehouse Ops Automation', description='Automate warehouse receiving, stock updates and dispatch notifications' WHERE id='gJ6xMGq2'");
      console.log('✅ One-time project rename applied');
    }
  } catch(e) { console.warn('Project rename skipped:', e.message); }

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