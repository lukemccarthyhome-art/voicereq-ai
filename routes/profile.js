const router = require('express').Router();
const db = require('../database-adapter');
const auth = require('../auth');

// === PROFILE ROUTES (for both admin and customer) ===

router.get('/profile', auth.authenticate, async (req, res) => {
  const fullUser = await db.getUserById(req.user.id) || req.user;
  let subscriptions = [];
  try { if (db.getSubscriptionsByUser) subscriptions = await db.getSubscriptionsByUser(req.user.id); } catch(e) {}
  res.render('profile', {
    user: { ...req.user, mfa_secret: fullUser.mfa_secret },
    subscriptions,
    title: 'Profile Settings',
    currentPage: req.user.role === 'admin' ? 'admin-profile' : 'customer-profile',
    message: req.query.message,
    error: req.query.error
  });
});

router.get('/help', auth.authenticate, (req, res) => {
  res.render('customer/help', { user: req.user, title: 'Help & Support', currentPage: 'help' });
});

router.get('/session-faq', auth.authenticate, (req, res) => {
  res.render('customer/session-faq', { user: req.user, title: 'Session FAQ', currentPage: 'help' });
});

router.post('/profile/name', auth.authenticate, async (req, res) => {
  try {
    const { displayName } = req.body;
    if (!displayName || !displayName.trim()) {
      return res.redirect('/profile?error=Display name cannot be empty');
    }
    const name = displayName.trim();
    if (name.length > 100) {
      return res.redirect('/profile?error=Display name is too long');
    }
    const user = await db.getUserById(req.user.id);
    await db.updateUser(req.user.id, user.email, name, user.company);
    res.redirect('/profile?message=Display name updated');
  } catch (e) {
    console.error('Update name error:', e);
    res.redirect('/profile?error=Failed to update display name');
  }
});

router.post('/profile/password', auth.authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.redirect('/profile?error=All password fields are required');
    }

    if (newPassword !== confirmPassword) {
      return res.redirect('/profile?error=New passwords do not match');
    }

    if (newPassword.length < 6) {
      return res.redirect('/profile?error=New password must be at least 6 characters');
    }

    const user = await db.getUserById(req.user.id);
    if (!auth.verifyPassword(currentPassword, user.password_hash)) {
      return res.redirect('/profile?error=Current password is incorrect');
    }

    const hashedPassword = auth.hashPassword(newPassword);
    await db.updateUserPassword(req.user.id, hashedPassword);

    res.redirect('/profile?message=Password updated successfully');
  } catch (e) {
    console.error('Update password error:', e);
    res.redirect('/profile?error=Failed to update password');
  }
});

module.exports = router;
