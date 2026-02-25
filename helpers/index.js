const { DATA_DIR, DESIGNS_DIR, PROPOSALS_DIR, uploadsDir } = require('./paths');
const { hashids, encodeProjectId, resolveProjectId } = require('./ids');
const { melb, melbDate, escapeHtml, renderText, summarizeRequirements, generateFollowupQuestions, buildWireframeHtml } = require('./formatting');
const { sendMortiEmail, sendSecurityAlert, sendInviteEmail, isValidEmail } = require('./email-sender');
const generationStatus = require('./generation-status');

module.exports = {
  DATA_DIR,
  DESIGNS_DIR,
  PROPOSALS_DIR,
  uploadsDir,
  hashids,
  encodeProjectId,
  resolveProjectId,
  melb,
  melbDate,
  escapeHtml,
  renderText,
  summarizeRequirements,
  generateFollowupQuestions,
  buildWireframeHtml,
  sendMortiEmail,
  sendSecurityAlert,
  sendInviteEmail,
  isValidEmail,
  generationStatus
};
