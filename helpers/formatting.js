// Melbourne timezone helpers
function melb(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleString('en-AU', { timeZone: 'Australia/Melbourne' });
}

function melbDate(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleDateString('en-AU', { timeZone: 'Australia/Melbourne' });
}

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

// renderText: convert plain text design content to safe HTML with formatting
function renderText(txt) {
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
}

// Lightweight summarizer for requirements -> return brief summary
function summarizeRequirements(text) {
  const lines = (text || '').split(/\n+/).map(l => l.trim()).filter(Boolean);
  return lines.slice(0, 5).join(' ');
}

function generateFollowupQuestions(summary) {
  return [
    'Confirm primary CTA and desired user action.',
    'Any branding or color guidelines to apply?',
    'Which data sources or files are authoritative for requirements?'
  ];
}

// Build a simple wireframe HTML for the design proposal
function buildWireframeHtml(projectId, summary) {
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

module.exports = {
  melb,
  melbDate,
  escapeHtml,
  renderText,
  summarizeRequirements,
  generateFollowupQuestions,
  buildWireframeHtml
};
