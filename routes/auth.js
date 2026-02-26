const router = require('express').Router();
const otplib = require('otplib');
const qrcode = require('qrcode');
const passport = require('passport');
const db = require('../database-adapter');
const auth = require('../auth');
const emails = require('../emails');
const { sendMortiEmail, sendSecurityAlert } = require('../helpers/email-sender');
const { loginLimiter } = require('../middleware/rate-limiters');

// Track failed logins per IP
const failedLogins = new Map();

// === MFA ROUTES ===

router.get('/login/mfa', async (req, res) => {
  const mfaPending = req.cookies.mfaPending;
  if (!mfaPending) return res.redirect('/login');
  res.render('login-mfa', { error: null });
});

router.post('/login/mfa', async (req, res) => {
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

router.get('/profile/mfa/prompt', auth.authenticate, async (req, res) => {
  res.render('mfa-prompt', { user: req.user });
});

router.get('/profile/mfa/setup', auth.authenticate, async (req, res) => {
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

router.post('/profile/mfa/setup', auth.authenticate, async (req, res) => {
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

// === LOGIN / LOGOUT ===

router.get('/login', async (req, res) => {
  if (req.cookies.authToken) {
    try {
      auth.authenticate(req, res, () => {
        return res.redirect(req.user.role === 'admin' ? '/admin' : '/dashboard');
      });
      return;
    } catch {}
  }
  const queryError = req.query.error ? decodeURIComponent(req.query.error.replace(/\+/g, ' ')) : null;
  res.render('login', { error: queryError, email: '', success: null });
});

router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.getUser(email);

    if (user && user.approved === 0) {
      return res.render('login', { error: 'Your account is pending approval. We\'ll be in touch soon.', email });
    }

    console.log('[LOGIN DEBUG]', email, 'found:', !!user, 'approved:', user?.approved, 'hash_len:', user?.password_hash?.length, 'pwd_hex:', Buffer.from(password).toString('hex'), 'verify:', user ? auth.verifyPassword(password, user.password_hash) : 'n/a');
    if (!user || !auth.verifyPassword(password, user.password_hash)) {
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

    failedLogins.delete(req.ip);

    sendSecurityAlert('Successful Login', { email: user.email, ip: req.ip, userAgent: req.get('User-Agent') });
    await db.logAction(user.id, 'login', { email: user.email }, req.ip);

    if (user.mfa_secret) {
      const mfaToken = require('jsonwebtoken').sign(
        { id: user.id, partial: true },
        auth.JWT_SECRET,
        { expiresIn: '5m' }
      );
      res.cookie('mfaPending', mfaToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 300000 });
      return res.redirect('/login/mfa');
    }

    const token = require('jsonwebtoken').sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      auth.JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 2 * 60 * 60 * 1000
    });

    if (!user.mfa_secret) {
      return res.redirect('/profile/mfa/prompt');
    }

    res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
  } catch (e) {
    console.error('Login error:', e);
    res.render('login', { error: 'Login failed', email: req.body.email || '' });
  }
});

router.get('/logout', async (req, res) => {
  res.clearCookie('authToken');
  res.clearCookie('mfaPending');
  res.redirect('/login');
});

// --- Shared OAuth login handler ---
async function handleOAuthLogin(req, res, email, displayName, provider) {
  if (!email) return res.redirect(`/login?error=No+email+from+${provider}`);

  let user = await db.getUser(email);

  if (user) {
    if (user.approved === 0) {
      return res.render('login', { error: 'Your account is pending approval. We\'ll be in touch soon.', email: '' });
    }
    sendSecurityAlert(`${provider} Login`, { email: user.email, ip: req.ip, userAgent: req.get('User-Agent') });
    await db.logAction(user.id, 'login', { email: user.email, method: provider.toLowerCase() }, req.ip);

    if (user.mfa_secret) {
      const mfaToken = require('jsonwebtoken').sign(
        { id: user.id, partial: true },
        auth.JWT_SECRET,
        { expiresIn: '5m' }
      );
      res.cookie('mfaPending', mfaToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 300000 });
      return res.redirect('/login/mfa');
    }

    const token = require('jsonwebtoken').sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      auth.JWT_SECRET,
      { expiresIn: '2h' }
    );
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 2 * 60 * 60 * 1000
    });

    if (!user.mfa_secret) {
      return res.redirect('/profile/mfa/prompt');
    }

    return res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
  }

  const bcrypt = require('bcryptjs');
  const placeholderHash = bcrypt.hashSync(require('crypto').randomBytes(32).toString('hex'), 10);
  await db.createPendingUser(email, displayName, '', '', placeholderHash);

  const tgToken = process.env.TELEGRAM_BOT_TOKEN;
  const tgChat = process.env.TELEGRAM_CHAT_ID;
  if (tgToken && tgChat) {
    try {
      const tgMsg = `🆕 New ${provider} signup!\n\nName: ${displayName}\nEmail: ${email}\n\nAccount is pending approval.`;
      await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: tgChat, text: tgMsg })
      });
    } catch (err) { console.error('Telegram notify failed:', err.message); }
  }

  const welcome = emails.welcomeEmail(displayName);
  sendMortiEmail(email, welcome.subject, welcome.html).catch(() => {});

  res.render('login', { error: null, success: 'Account created! We\'ll review and approve it shortly.', email: '' });
}

// --- Google OAuth Routes ---
router.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_OAUTH_CLIENT_ID) return res.redirect('/login?error=Google+sign-in+not+configured');
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
});

router.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', { session: false, failureRedirect: '/login?error=Google+sign-in+failed' }, async (err, profile) => {
    if (err || !profile) return res.redirect('/login?error=Google+sign-in+failed');
    try {
      const email = profile.emails && profile.emails[0] && profile.emails[0].value;
      const displayName = profile.displayName || (email ? email.split('@')[0] : 'Google User');
      await handleOAuthLogin(req, res, email, displayName, 'Google');
    } catch (e) {
      console.error('Google OAuth error:', e);
      res.redirect('/login?error=Something+went+wrong');
    }
  })(req, res, next);
});

// --- Microsoft OAuth Routes ---
router.get('/auth/microsoft', (req, res, next) => {
  if (!process.env.MICROSOFT_CLIENT_ID) return res.redirect('/login?error=Microsoft+sign-in+not+configured');
  passport.authenticate('microsoft', { scope: ['user.read'], session: false })(req, res, next);
});

router.get('/auth/microsoft/callback', (req, res, next) => {
  passport.authenticate('microsoft', { session: false, failureRedirect: '/login?error=Microsoft+sign-in+failed' }, async (err, profile) => {
    if (err || !profile) return res.redirect('/login?error=Microsoft+sign-in+failed');
    try {
      const email = profile.emails && profile.emails[0] && profile.emails[0].value;
      const displayName = profile.displayName || (email ? email.split('@')[0] : 'Microsoft User');
      await handleOAuthLogin(req, res, email, displayName, 'Microsoft');
    } catch (e) {
      console.error('Microsoft OAuth error:', e);
      res.redirect('/login?error=Something+went+wrong');
    }
  })(req, res, next);
});

module.exports = router;
