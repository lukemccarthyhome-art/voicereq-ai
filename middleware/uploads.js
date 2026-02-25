const multer = require('multer');
const { uploadsDir } = require('../helpers/paths');

const upload = multer({
  dest: uploadsDir,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

const importUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

module.exports = { upload, importUpload };
