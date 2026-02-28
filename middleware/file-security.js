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

// --- MetaDefender Cloud (OPSWAT) virus scanning ---

const METADEFENDER_API_KEY = process.env.METADEFENDER_API_KEY;
const SCAN_POLL_INTERVAL = 1000; // 1s between polls
const SCAN_TIMEOUT = 30000;      // 30s max wait

/**
 * Scans uploaded file for malware using MetaDefender Cloud API (30+ AV engines).
 * Blocks upload if API key is missing or scan fails — no silent skipping.
 * Must run AFTER validateFileType.
 */
async function scanForMalware(req, res, next) {
  if (!req.file) return next();

  if (!METADEFENDER_API_KEY) {
    console.error('MetaDefender: METADEFENDER_API_KEY not set — blocking upload.');
    cleanupFile(req.file.path);
    return res.status(503).json({ error: 'File uploads are temporarily unavailable (virus scanning not configured).' });
  }

  try {
    const fileBuffer = fs.readFileSync(req.file.path);

    // Submit file for scanning
    const submitRes = await fetch('https://api.metadefender.com/v4/file', {
      method: 'POST',
      headers: {
        'apikey': METADEFENDER_API_KEY,
        'Content-Type': 'application/octet-stream',
        'filename': req.file.originalname,
      },
      body: fileBuffer,
    });

    if (!submitRes.ok) {
      const errBody = await submitRes.text();
      console.error('MetaDefender: submit error', submitRes.status, errBody);
      cleanupFile(req.file.path);
      return res.status(503).json({ error: 'File upload failed: virus scan service unavailable.' });
    }

    const { data_id } = await submitRes.json();
    if (!data_id) {
      console.error('MetaDefender: no data_id returned');
      cleanupFile(req.file.path);
      return res.status(503).json({ error: 'File upload failed: virus scan service error.' });
    }

    // Poll for results
    const started = Date.now();
    let result;
    while (Date.now() - started < SCAN_TIMEOUT) {
      await new Promise(r => setTimeout(r, SCAN_POLL_INTERVAL));

      const pollRes = await fetch(`https://api.metadefender.com/v4/file/${data_id}`, {
        headers: { 'apikey': METADEFENDER_API_KEY },
      });

      if (!pollRes.ok) {
        console.error('MetaDefender: poll error', pollRes.status);
        continue;
      }

      result = await pollRes.json();
      if (result.process_info && result.process_info.progress_percentage === 100) break;
    }

    if (!result || !result.process_info || result.process_info.progress_percentage !== 100) {
      console.error('MetaDefender: scan timed out for', req.file.originalname);
      cleanupFile(req.file.path);
      return res.status(503).json({ error: 'File upload failed: virus scan timed out.' });
    }

    // Check result
    const detected = result.scan_results && result.scan_results.total_detected_avs > 0;
    const verdict = result.scan_results && result.scan_results.scan_all_result_a;

    if (detected) {
      console.warn(`MetaDefender: THREAT — ${req.file.originalname} — ${verdict} (${result.scan_results.total_detected_avs}/${result.scan_results.total_avs} engines)`);
      cleanupFile(req.file.path);
      return res.status(400).json({ error: 'File rejected: potential security threat detected.' });
    }

    console.log(`MetaDefender: clean — ${req.file.originalname} (${result.scan_results.total_avs} engines, ${result.scan_results.total_time}ms)`);
    next();
  } catch (err) {
    console.error('MetaDefender: scan error:', err.message);
    cleanupFile(req.file.path);
    return res.status(503).json({ error: 'File upload failed: virus scan error.' });
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
