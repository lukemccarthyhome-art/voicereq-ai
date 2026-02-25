const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const db = require('../database-adapter');
const auth = require('../auth');
const emails = require('../emails');
const { sendMortiEmail } = require('../helpers/email-sender');
const { signupLimiter, contactLimiter } = require('../middleware/rate-limiters');

// Signup page
router.get('/signup', (req, res) => {
  res.render('signup');
});

router.post('/signup', signupLimiter, async (req, res) => {
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

    const existing = await db.getUser(email);
    if (existing) {
      return res.render('signup', { error: 'An account with this email already exists.', formData: req.body });
    }

    const bcrypt = require('bcryptjs');
    const hashedPassword = bcrypt.hashSync(password, 10);
    const signupResult = await db.createPendingUser(email, name, company, phone, hashedPassword);

    if (signupResult && signupResult.lastInsertRowid) {
      await db.linkPendingShares(signupResult.lastInsertRowid, email);
    }

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

    const welcome = emails.welcomeEmail(name);
    sendMortiEmail(email, welcome.subject, welcome.html).catch(() => {});

    res.render('signup', { success: true });
  } catch (e) {
    console.error('Signup error:', e);
    res.render('signup', { error: 'Something went wrong. Please try again.', formData: req.body });
  }
});

// AI Readiness Review page
router.get('/ai-readiness', (req, res) => {
  res.render('ai-readiness', { currentPage: 'ai-readiness' });
});

// About page
router.get('/about', (req, res) => {
  res.render('about');
});

// Contact page
router.get('/contact', (req, res) => {
  res.render('contact');
});

router.post('/contact', contactLimiter, async (req, res) => {
  const { name, email, company, subject, message } = req.body;
  if (!name || !email || !message) {
    return res.render('contact', { error: 'Please fill in all required fields.', formData: req.body });
  }

  const subjectLabels = { general: 'General Enquiry', 'new-project': 'New Project', quote: 'Request a Quote', support: 'Existing Project Support' };
  const subjectLine = `[Morti Projects] ${subjectLabels[subject] || 'Enquiry'} from ${name}`;
  const body = `Name: ${name}\nEmail: ${email}\nCompany: ${company || 'N/A'}\nType: ${subjectLabels[subject] || subject}\n\nMessage:\n${message}`;

  const enquiriesDir = path.join(process.env.DATA_DIR || path.join(__dirname, '..', 'data'), 'enquiries');
  if (!fs.existsSync(enquiriesDir)) fs.mkdirSync(enquiriesDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  fs.writeFileSync(path.join(enquiriesDir, `enquiry-${timestamp}.txt`), `${subjectLine}\nDate: ${new Date().toISOString()}\n\n${body}`);

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
    }
  }

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

// Root/landing
router.get('/', (req, res) => {
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

module.exports = router;
