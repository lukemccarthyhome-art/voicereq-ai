// In-memory generation status tracking
// { [projectId]: { type: 'proposal'|'design', status: 'generating'|'done'|'error', error?: string, startedAt: number } }
const generationStatus = {};

module.exports = generationStatus;
