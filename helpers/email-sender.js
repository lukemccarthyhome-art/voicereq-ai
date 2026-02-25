const nodemailer = require('nodemailer');

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

// Security Alert Helper (Telegram)
async function sendSecurityAlert(type, details) {
  const db = require('../database-adapter');
  const { melb } = require('./formatting');

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

// Send invite email (graceful without SMTP)
async function sendInviteEmail(to, inviterName, projectName, permission, signupLink, projectLink) {
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
}

// Email validation helper
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

module.exports = { sendMortiEmail, sendSecurityAlert, sendInviteEmail, isValidEmail };
