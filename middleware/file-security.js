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

// --- ClamAV malware scanning ---

let clamScanner = null;
let clamInitAttempted = false;
let clamAvailable = false;

async function initClam() {
  if (clamInitAttempted) return clamAvailable;
  clamInitAttempted = true;

  try {
    const NodeClam = require('clamscan');
    clamScanner = await new NodeClam().init({
      removeInfected: false,
      quarantineInfected: false,
      debugMode: false,
      clamdscan: {
        socket: null,
        host: '127.0.0.1',
        port: 3310,
        localFallback: true,
      },
      preference: 'clamdscan',
    });
    clamAvailable = true;
    console.log('ClamAV: scanner initialized successfully');
  } catch (err) {
    clamAvailable = false;
    console.warn('ClamAV: not available — uploads will proceed without virus scanning.', err.message);
  }

  return clamAvailable;
}

/**
 * Scans uploaded file for malware using ClamAV.
 * Gracefully skips if ClamAV is not installed.
 * Must run AFTER validateFileType.
 */
async function scanForMalware(req, res, next) {
  if (!req.file) return next();

  const available = await initClam();
  if (!available) return next();

  try {
    const { isInfected, viruses } = await clamScanner.isInfected(req.file.path);

    if (isInfected) {
      console.warn(`ClamAV: INFECTED file detected — ${req.file.originalname} — viruses: ${viruses.join(', ')}`);
      cleanupFile(req.file.path);
      return res.status(400).json({ error: 'File rejected: potential security threat detected' });
    }

    next();
  } catch (err) {
    // Scan failure should not block uploads — log and continue
    console.error('ClamAV: scan error:', err.message);
    next();
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
