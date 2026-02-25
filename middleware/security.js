const xss = require('xss');

// Input Sanitization Middleware
const sanitizeInput = (req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key]);
      }
    }
  }
  next();
};

// Cloudflare-only Middleware
const cloudflareOnly = (req, res, next) => {
  // TEMPORARILY DISABLED TO DEBUG 502 ERROR
  return next();
};

module.exports = { sanitizeInput, cloudflareOnly };
