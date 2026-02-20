// Database adapter - chooses between SQLite and PostgreSQL based on environment
const dbBackend = process.env.DATABASE_URL ? require('./database-pg') : require('./database');

if (process.env.DATABASE_URL) {
  console.log('🐘 Using PostgreSQL database');
} else {
  console.log('📄 Using SQLite database');
}

// Stub any missing functions so server.js never crashes on db.xxx is not a function
const stubs = {
  logAction: async () => {},
  getProjectShares: async () => [],
  getSharedProjects: async () => [],
  addProjectShare: async () => ({ changes: 0 }),
  updateSharePermission: async () => {},
  removeShare: async () => {},
  acceptShare: async () => {},
  getShareByToken: async () => null,
  getShareById: async () => null,
  getShareByProjectAndUser: async () => null,
  getShareByProjectAndEmail: async () => null,
  acceptSharesByEmail: async () => {},
  getAllSessions: async () => [],
};

for (const [fn, stub] of Object.entries(stubs)) {
  if (typeof dbBackend[fn] !== 'function') {
    console.warn(`⚠️  DB adapter missing: ${fn} — using stub`);
    dbBackend[fn] = stub;
  }
}

module.exports = dbBackend;