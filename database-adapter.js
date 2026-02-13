// Database adapter - chooses between SQLite and PostgreSQL based on environment
if (process.env.DATABASE_URL) {
  console.log('🐘 Using PostgreSQL database');
  module.exports = require('./database-pg');
} else {
  console.log('📄 Using SQLite database');
  module.exports = require('./database');
}