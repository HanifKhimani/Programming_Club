// export the model
const resourcedb = require('../models/resource.js');
const User = require('../models/User.js');
const { createError } = require('../custom_error/error.js');

module.exports.Resource_get_all = async (req, res, next) => {
  try {
    const resources = await resourcedb.find();
    resources.sort((a, b) => {
      return new String(b.title).localeCompare(a.title);
    });
    if (req.isAuthenticated()) {
      const foundUser = await User.findById(req.user.id);
      if (foundUser) {
        res.render('../views/resource/resource_home.ejs', {
          userid: foundUser._id,
          backend_resources: resources,
          is_admin: foundUser.isadmin,
          is_member: foundUser.ismember,
        });
      } else {
        res.send('User is not authenticated. Please try again.');
      }
    }
  } catch (error) {
    res.send('There was an error. Please try again.');
  }
};