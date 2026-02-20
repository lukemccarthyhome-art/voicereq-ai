// emails.js — Morti Projects email templates and send helpers
// Uses the sendMortiEmail() function from server.js (passed in or required)

const BASE_URL = 'https://projects.morti.com.au';

function wrap(bodyHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 0;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
  <!-- Header -->
  <tr><td style="background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);padding:32px 40px;text-align:center;">
    <span style="font-size:28px;color:#ffffff;font-weight:700;letter-spacing:0.5px;">◆ Morti</span>
    <div style="color:rgba(255,255,255,0.8);font-size:13px;margin-top:4px;letter-spacing:1px;">PROJECTS</div>
  </td></tr>
  <!-- Body -->
  <tr><td style="padding:40px 40px 32px;">
    ${bodyHtml}
  </td></tr>
  <!-- Footer -->
  <tr><td style="padding:24px 40px;background:#f8fafc;border-top:1px solid #e2e8f0;text-align:center;">
    <p style="margin:0;color:#94a3b8;font-size:13px;line-height:1.6;">
      © ${new Date().getFullYear()} Morti Pty Ltd · Australia<br>
      <a href="${BASE_URL}" style="color:#4f46e5;text-decoration:none;">projects.morti.com.au</a>
    </p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;
}

function btn(text, url) {
  return `<p style="text-align:center;margin:32px 0;">
    <a href="${url}" style="display:inline-block;background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#ffffff;padding:14px 36px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px;">${text}</a>
  </p>`;
}

const S = {
  h: 'style="margin:0 0 16px;color:#1e293b;font-size:22px;font-weight:700;"',
  p: 'style="margin:0 0 16px;color:#475569;font-size:15px;line-height:1.7;"',
};

// ─── Email builders ──────────────────────────────────────────

function welcomeEmail(name) {
  return {
    subject: 'Welcome to Morti Projects',
    html: wrap(`
      <h2 ${S.h}>Welcome${name ? ', ' + name : ''}! 👋</h2>
      <p ${S.p}>Thanks for signing up to <strong>Morti Projects</strong> — we're excited to have you.</p>
      <p ${S.p}>Your account is now <strong>under review</strong>. Our team will check your details and approve your account shortly — usually within 24 hours.</p>
      <p ${S.p}>Once approved, you'll receive another email and can log in to start capturing your project requirements through voice or chat.</p>
      ${btn('Visit Morti Projects', BASE_URL + '/login')}
      <p ${S.p}>Questions? Just reply to this email or contact us at <a href="mailto:info@morti.com.au" style="color:#4f46e5;">info@morti.com.au</a>.</p>
    `)
  };
}

function accountApprovedEmail(name) {
  return {
    subject: 'Your Morti Projects Account is Ready',
    html: wrap(`
      <h2 ${S.h}>You're in${name ? ', ' + name : ''}! 🎉</h2>
      <p ${S.p}>Great news — your <strong>Morti Projects</strong> account has been approved and is ready to use.</p>
      <p ${S.p}>Log in now to create a project and start capturing your requirements through voice or chat. Our AI will help structure everything into a clear solution design.</p>
      ${btn('Log In Now', BASE_URL + '/login')}
      <p ${S.p}>Questions? Reply to this email or contact us at <a href="mailto:info@morti.com.au" style="color:#4f46e5;">info@morti.com.au</a>.</p>
    `)
  };
}

function designReadyEmail(projectName, projectId) {
  return {
    subject: `Your Solution Design is Ready — ${projectName}`,
    html: wrap(`
      <h2 ${S.h}>Your design is ready! 📐</h2>
      <p ${S.p}>The solution design for <strong>${projectName}</strong> has been published and is ready for your review.</p>
      <p ${S.p}>It covers the technical architecture, key components, and implementation approach based on your requirements. Take a look and let us know if anything needs adjusting.</p>
      ${btn('View Design', BASE_URL + '/customer/projects/' + projectId + '/design')}
      <p ${S.p}>Have feedback? You can discuss changes directly within the project, or reply to this email.</p>
    `)
  };
}

function proposalReadyEmail(projectName, projectId) {
  return {
    subject: `Your Project Proposal is Ready — ${projectName}`,
    html: wrap(`
      <h2 ${S.h}>Your proposal is ready! 📋</h2>
      <p ${S.p}>The project proposal for <strong>${projectName}</strong> has been published and is ready for your review.</p>
      <p ${S.p}>It includes the project scope, timeline, and pricing based on your solution design. Review the details and approve when you're ready to proceed.</p>
      ${btn('View Proposal', BASE_URL + '/customer/projects/' + projectId + '/proposal')}
      <p ${S.p}>Questions about the proposal? Reply to this email or discuss within the project.</p>
    `)
  };
}

module.exports = { welcomeEmail, accountApprovedEmail, designReadyEmail, proposalReadyEmail };
