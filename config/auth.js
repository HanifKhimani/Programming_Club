module.exports = {
  ensureAuthenticated: function (req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    req.flash('error_msg', 'Please log in to view that resource');
    res.redirect('/users/login');
  },
  forwardAuthenticated: function (req, res, next) {
    if (!req.isAuthenticated()) {
      return next();
    }
    res.redirect('/dashboard');
  },
  isAdmin: function (req, res, next) {
    if (req.isAuthenticated() && req.user.isadmin && req.user.ismember) {
      return next();
    } else if (req.user.isadmin == 0 && req.user.ismember == 0) {
      req.flash('error_msg', 'You are not admin');
      res.redirect('/admin/');
    } else {
      req.flash('error_msg', 'Please log in to view that resource');
      res.redirect('/admin/');
    }
  },
  adminforwardAuthenticated: function (req, res, next) {
    if (!req.isAuthenticated() && !req.user.isadmin && !req.user.ismember) {
      return next();
    }
    res.redirect('/admin/dashboard');
  },
};
