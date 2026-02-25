const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const DESIGNS_DIR = path.join(DATA_DIR, 'designs');
const PROPOSALS_DIR = path.join(DATA_DIR, 'proposals');

// Uploads directory — use persistent storage if available
let uploadsDir;
if (process.env.DATA_DIR) {
  try {
    fs.mkdirSync(process.env.DATA_DIR, { recursive: true });
    uploadsDir = path.join(process.env.DATA_DIR, 'uploads');
  } catch (e) {
    console.warn(`DATA_DIR ${process.env.DATA_DIR} not writable, using local uploads`);
    uploadsDir = path.join(__dirname, '..', 'uploads');
  }
} else {
  uploadsDir = path.join(__dirname, '..', 'uploads');
}

// Ensure directories exist
fs.mkdirSync(uploadsDir, { recursive: true });
fs.mkdirSync(DESIGNS_DIR, { recursive: true });
fs.mkdirSync(PROPOSALS_DIR, { recursive: true });
fs.mkdirSync(path.join(__dirname, '..', 'data'), { recursive: true });

module.exports = { DATA_DIR, DESIGNS_DIR, PROPOSALS_DIR, uploadsDir };
