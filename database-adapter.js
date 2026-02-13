// Database adapter - chooses between SQLite and PostgreSQL based on environment
const dbBackend = process.env.DATABASE_URL ? require('./database-pg') : require('./database');

if (process.env.DATABASE_URL) {
  console.log('🐘 Using PostgreSQL database');
} else {
  console.log('📄 Using SQLite database');
}

// Proxy logAction to ensure it doesn't crash if backend doesn't export it yet
dbBackend.logAction = dbBackend.logAction || (async () => {});

module.exports = dbBackend;