const fs = require('fs');
const path = require('path');

// --- File type allowlist ---

// Extensions that have detectable magic bytes
const BINARY_ALLOWLIST = {
  '.pdf':  ['application/pdf'],
  '.doc':  ['application/msword', 'application/x-cfb'],
  '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
  '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
  '.xls':  ['application/vnd.ms-excel', 'application/x-cfb'],
  '.pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'],
  '.rtf':  ['application/rtf'],
  '.png':  ['image/png'],
  '.jpg':  ['image/jpeg'],
  '.jpeg': ['image/jpeg'],
  '.gif':  ['image/gif'],
  '.webp': ['image/webp'],
  '.bmp':  ['image/bmp'],
};

// Text-based extensions — no magic bytes to detect, allowed by extension alone
const TEXT_ALLOWLIST = new Set([
  '.txt', '.md', '.csv', '.json', '.xml', '.yaml', '.yml',
  '.html', '.css', '.js', '.ts', '.py', '.java', '.rb', '.svg'
]);

const ALL_ALLOWED_EXTENSIONS = new Set([
  ...Object.keys(BINARY_ALLOWLIST),
  ...TEXT_ALLOWLIST
]);

// Lazy-loaded file-type (ESM module)
let fileTypeFromBuffer;

async function getFileType(buffer) {
  if (!fileTypeFromBuffer) {
    const mod = await import('file-type');
    fileTypeFromBuffer = mod.fileTypeFromBuffer;
  }
  return fileTypeFromBuffer(buffer);
}

/**
 * Validates uploaded file type against allowlist and verifies magic bytes.
 * Must run AFTER multer saves the file to disk.
 */
async function validateFileType(req, res, next) {
  if (!req.file) return next();

  const ext = path.extname(req.file.originalname).toLowerCase();

  // Check extension against allowlist
  if (!ALL_ALLOWED_EXTENSIONS.has(ext)) {
    cleanupFile(req.file.path);
    return res.status(400).json({
      error: `File type '${ext}' is not allowed. Accepted types: documents, text/code files, and images.`
    });
  }

  // Text-based files have no magic bytes — allow by extension
  if (TEXT_ALLOWLIST.has(ext)) {
    return next();
  }

  // Binary files — verify magic bytes match expected type
  try {
    const buffer = Buffer.alloc(4100);
    const fd = fs.openSync(req.file.path, 'r');
    const bytesRead = fs.readSync(fd, buffer, 0, 4100, 0);
    fs.closeSync(fd);

    const detected = await getFileType(buffer.subarray(0, bytesRead));

    if (!detected) {
      cleanupFile(req.file.path);
      return res.status(400).json({
        error: `Unable to verify file contents for '${req.file.originalname}'. The file may be corrupted or empty.`
      });
    }

    const expectedMimes = BINARY_ALLOWLIST[ext];
    if (!expectedMimes.includes(detected.mime)) {
      cleanupFile(req.file.path);
      return res.status(400).json({
        error: `File content does not match its extension. Expected ${ext} but detected ${detected.mime}.`
      });
    }

    next();
  } catch (err) {
    console.error('File type validation error:', err.message);
    cleanupFile(req.file.path);
    return res.status(400).json({ error: 'File validation failed.' });
  }
}

// --- Cloudmersive virus scanning ---

const CLOUDMERSIVE_API_KEY = process.env.CLOUDMERSIVE_API_KEY;

/**
 * Scans uploaded file for malware using Cloudmersive Virus Scan API.
 * Gracefully skips if API key is not configured.
 * Must run AFTER validateFileType.
 */
async function scanForMalware(req, res, next) {
  if (!req.file) return next();

  if (!CLOUDMERSIVE_API_KEY) {
    console.warn('Cloudmersive: CLOUDMERSIVE_API_KEY not set — skipping virus scan.');
    return next();
  }

  try {
    const fileBuffer = fs.readFileSync(req.file.path);
    const boundary = '----FormBoundary' + Math.random().toString(36).slice(2);

    const bodyParts = [
      `--${boundary}\r\n`,
      `Content-Disposition: form-data; name="inputFile"; filename="${req.file.originalname}"\r\n`,
      `Content-Type: ${req.file.mimetype || 'application/octet-stream'}\r\n\r\n`,
    ];

    const bodyStart = Buffer.from(bodyParts.join(''));
    const bodyEnd = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Buffer.concat([bodyStart, fileBuffer, bodyEnd]);

    const response = await fetch('https://api.cloudmersive.com/virus/scan/file', {
      method: 'POST',
      headers: {
        'Apikey': CLOUDMERSIVE_API_KEY,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
      },
      body,
    });

    if (!response.ok) {
      console.error('Cloudmersive: API error', response.status, response.statusText);
      return next(); // Don't block uploads on API errors
    }

    const result = await response.json();

    if (result.CleanResult === false) {
      const virusNames = (result.FoundViruses || []).map(v => v.VirusName).join(', ');
      console.warn(`Cloudmersive: INFECTED — ${req.file.originalname} — ${virusNames}`);
      cleanupFile(req.file.path);
      return res.status(400).json({ error: 'File rejected: potential security threat detected.' });
    }

    console.log(`Cloudmersive: clean — ${req.file.originalname}`);
    next();
  } catch (err) {
    console.error('Cloudmersive: scan error:', err.message);
    next(); // Don't block uploads on network errors
  }
}

function cleanupFile(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (e) {
    console.error('Failed to cleanup rejected file:', e.message);
  }
}

module.exports = { validateFileType, scanForMalware };
