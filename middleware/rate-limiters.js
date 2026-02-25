const rateLimit = require('express-rate-limit');

const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, message: 'Too many requests' });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Too many login attempts' });
const uploadLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20, message: 'File upload limit reached (20 files per hour). Please try again later.' });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: 'Too many signup attempts, please try again later.' });
const contactLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: 'Too many enquiries, please try again later.' });

module.exports = { generalLimiter, loginLimiter, uploadLimiter, signupLimiter, contactLimiter };
