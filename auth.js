const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { getUser } = require('./database-adapter');

const JWT_SECRET = process.env.JWT_SECRET || 'voicereq-default-secret-change-in-production';

const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user.id, 
      email: user.email, 
      role: user.role,
      name: user.name 
    },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
};

const verifyPassword = (plainPassword, hashedPassword) => {
  return bcrypt.compareSync(plainPassword, hashedPassword);
};

const hashPassword = (plainPassword) => {
  return bcrypt.hashSync(plainPassword, 10);
};

const authenticate = async (req, res, next) => {
  const token = req.cookies.authToken;
  
  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = require('./database-adapter');
    
    // Check if user has completed MFA setup
    const user = await db.getUserById(decoded.id);
    
    // If user exists and hasn't set up MFA, redirect to setup
    // Exception: Allow access to the setup routes and logout
    if (user && !user.mfa_secret && !req.path.startsWith('/profile/mfa') && !req.path.startsWith('/logout')) {
      return res.redirect('/profile/mfa/setup');
    }

    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('authToken');
    return res.redirect('/login');
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).render('error', { 
      message: 'Access denied. Admin privileges required.',
      user: req.user 
    });
  }
  next();
};

const requireCustomer = (req, res, next) => {
  if (req.user.role !== 'customer') {
    return res.status(403).render('error', { 
      message: 'Access denied. Customer account required.',
      user: req.user 
    });
  }
  next();
};

module.exports = {
  generateToken,
  verifyPassword,
  hashPassword,
  authenticate,
  requireAdmin,
  requireCustomer,
  JWT_SECRET
};