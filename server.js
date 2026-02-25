const express = require('express');
const path = require('path');
const fs = require('fs');
const https = require('https');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

require('dotenv').config();

// Crash logging — write to persistent disk so we can diagnose Render crashes
const CRASH_LOG = process.env.DATA_DIR ? path.join(process.env.DATA_DIR, 'crash.log') : null;
function logCrash(label, err) {
  const msg = `[${new Date().toISOString()}] ${label}: ${err?.stack || err?.message || err}\n`;
  console.error(msg);
  if (CRASH_LOG) try { fs.appendFileSync(CRASH_LOG, msg); } catch {}
}
process.on('uncaughtException', (err) => { logCrash('UNCAUGHT', err); process.exit(1); });
process.on('unhandledRejection', (err) => { logCrash('UNHANDLED_REJECTION', err); });

// Import database and authentication
const db = require('./database-adapter');
const auth = require('./auth');

// Import helpers
const { uploadsDir } = require('./helpers/paths');
const { encodeProjectId, resolveProjectId } = require('./helpers/ids');
const { melb, melbDate, renderText } = require('./helpers/formatting');

// Import middleware
const { generalLimiter, sanitizeInput, cloudflareOnly } = require('./middleware');

// === Express App Setup ===
const app = express();
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = 3443;

// Trust proxy (Render terminates SSL at load balancer)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(generalLimiter);

// Capture raw body for Stripe webhook verification — MUST be before express.json()
app.use('/api/billing/stripe-webhook', express.raw({ type: 'application/json' }));

// Body parsing
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
process.removeAllListeners('uncaughtException');
process.removeAllListeners('unhandledRejection');
process.on('uncaughtException', (err) => {
  const reqDump = `\n--- Last ${recentRequests.length} requests ---\n${recentRequests.join('\n')}\n--- End requests ---\n`;
  const msg = `[${new Date().toISOString()}] UNCAUGHT: ${err?.stack || err?.message || err}${reqDump}`;
  console.error(msg);
  if (CRASH_LOG) try { fs.appendFileSync(CRASH_LOG, msg); } catch {}
  process.exit(1);
});
process.on('unhandledRejection', (err) => {
  const reqDump = `\n--- Last ${recentRequests.length} requests ---\n${recentRequests.join('\n')}\n--- End requests ---\n`;
  const msg = `[${new Date().toISOString()}] UNHANDLED_REJECTION: ${err?.stack || err?.message || err}${reqDump}`;
  console.error(msg);
  if (CRASH_LOG) try { fs.appendFileSync(CRASH_LOG, msg); } catch {}
});

// Security middleware
app.use(cloudflareOnly);
app.use(sanitizeInput);

// --- Google OAuth (Passport) ---
if (process.env.GOOGLE_OAUTH_CLIENT_ID && process.env.GOOGLE_OAUTH_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_OAUTH_CLIENT_ID,
    clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  }, (accessToken, refreshToken, profile, done) => {
    done(null, profile);
  }));
  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));
  app.use(passport.initialize());
}

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Make helpers available to all templates
app.use((req, res, next) => {
  res.locals.melb = melb;
  res.locals.melbDate = melbDate;
  res.locals.encodeId = encodeProjectId;
  res.locals.renderText = renderText;
  next();
});

// Decode hashed IDs in route params (backward compatible with numeric IDs)
app.param('id', (req, res, next, val) => {
  req.params.id = resolveProjectId(val);
  next();
});

// Serve uploaded files (behind auth + ownership check)
app.use('/uploads', async (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).send('Unauthorized');
  try {
    const decoded = require('jsonwebtoken').verify(token, auth.JWT_SECRET);
    const user = await db.getUserById(decoded.id);
    if (!user) return res.status(401).send('Unauthorized');
    if (user.role === 'admin') return next();
    const filename = decodeURIComponent(req.path.replace(/^\//, ''));
    let file;
    if (db.queryOne) {
      file = await db.queryOne('SELECT f.*, p.user_id FROM files f JOIN projects p ON f.project_id = p.id WHERE f.filename = $1 OR f.original_name = $2', [filename, filename]);
    }
    if (!file) return res.status(403).send('Forbidden');
    if (file.user_id !== user.id) {
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

// === Mount Route Modules ===
// Order matters: more specific routes before parameterized ones
app.use(require('./routes/public-pages'));
app.use(require('./routes/auth'));
app.use(require('./routes/profile'));
app.use(require('./routes/admin-dashboard'));
app.use(require('./routes/admin-projects'));
app.use(require('./routes/design'));
app.use(require('./routes/proposals'));
app.use(require('./routes/sharing'));
app.use(require('./routes/customer-mobile'));
app.use(require('./routes/customer'));
app.use(require('./routes/api'));
app.use(require('./routes/billing-routes'));

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
