// Database adapter - chooses between SQLite and PostgreSQL based on environment
if (process.env.DATABASE_URL) {
  console.log('🐘 Using PostgreSQL database');
  module.exports = require('./database-pg');
} else {
  console.log('📄 Using SQLite database');
  try {
    module.exports = require('./database');
  } catch (e) {
    console.error('❌ SQLite failed to load:', e.message);
    console.log('💡 Set DATABASE_URL for PostgreSQL');
    process.exit(1);
  }
}