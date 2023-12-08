const express = require('express');
const router = express.Router();
const passport = require('passport');
router.use(express.static('public'));
const { ensureAuthenticated, isAdmin } = require('../config/auth');

var bodyParser = require('body-parser');

router.use(bodyParser.json({ type: 'application/json' }));

//Load User model
const User = require('../models/User');
const Event = require('../models/Event');
const Feedback = require('../models/Feedback');

router.get(
  '/',
  (req, res) => res.render('admin')
  //console.log(req.user)
);

//admin Login
router.post('/', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash('error_msg', 'Invalid username or password');
      return res.redirect('/admin/');
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      if (typeof window !== 'undefined') {
        localStorage.setItem('user', JSON.stringify(user));
      }
      return res.redirect('/admin/dashboard');
    });
  })(req, res, next);
});

router.get(
  '/user',
  isAdmin,
  async (req, res) => {
    const users = await User.find();
    users.sort((a, b) => {
      return new String(a.email).localeCompare(b.email);
    });
    res.render('user_data', {
      user: req.user,
      user_data: users,
    });
  }
  //console.log(req.user)
);

router.get(
  '/admin_dashboard',
  isAdmin,
  async (req, res) => {
    const users = await User.find();
    users.sort((a, b) => {
      return new String(a.email).localeCompare(b.email);
    });
    res.render('admin_data', {
      user: req.user,
      admin_data: users,
    });
  }
  //console.log(req.user)
);

router.get(
  '/dashboard',
  isAdmin,
  async (req, res) => {
    const user_ict = await User.find();

    const size = 8;
    const vector = new Array(size).fill(0);
    //console.log(vector); // [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    for (let i = 0; i < user_ict.length; i++) {
      if (user_ict[i].programe == 'M.Sc - IT') {
        vector[0] += 1;
      } else if (user_ict[i].programe == 'M.Sc - DS') {
        vector[1] += 1;
      } else if (user_ict[i].programe == 'M.Tech - EC') {
          vector[2] += 1;
      } else if (user_ict[i].programe == 'M.Tech - ICT') {
          vector[3] += 1;
      } else if (user_ict[i].programe == 'B.Tech - ICT') {
        vector[4] += 1;
      } else if (user_ict[i].programe == 'B.Tech - ICT (CS)') {
        vector[5] += 1;
      } else if (user_ict[i].programe == 'B.Tech - MNC') {
        vector[6] += 1;
      } else if (user_ict[i].programe == 'B.Tech - EVD') {
        vector[7] += 1;
      }
    }

    const year = new Array(4).fill(0);
    //console.log(vector); // [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    for (let i = 0; i < user_ict.length; i++) {
      if (user_ict[i].batch == '1st Year') {
        year[0] += 1;
      } else if (user_ict[i].batch == '2nd Year') {
        year[1] += 1;
      } else if (user_ict[i].batch == '3rd Year') {
        year[2] += 1;
      } else if (user_ict[i].batch == '4rd Year') {
        year[3] += 1;
      }
    }

    //console.log(map);
    //console.log(vector);

    const new_vector = JSON.stringify(vector);
    const new_year = JSON.stringify(year);

    res.render('admin_dashboard', {
      user: req.user,
      programme_data: new_vector,
      year_data: new_year,
    });
  }

  //console.log(req.user)
);

router.get(
  '/event',
  isAdmin,
  (req, res) =>
    res.render('manage_event', {
      user: req.user,
    })
  //console.log(req.user)
);

router.get('/edit_event/:id', async (req, res) => {
  const { id } = req.params;

  await Event.findOne({ _id: id }).then((data) => {
    //console.log(data);
    res.render('edit_event', {
      user: req.user,
      id: data._id,
      name: data.name,
      date: data.date,
      description: data.description,
      duration: data.duration,
      venue: data.venue,
    });
  });
});

router.post('/edit_event/:id', (req, res) => {
  const { id } = req.params;
  const { name, date, description, duration, venue } = req.body;

  let errors = [];

  //console.log(programe);
  //check required fields
  if (!name || !date || !duration || !venue) {
    errors.push({ msg: 'Please enter all fields' });
  }

  //check date and time
  var date1 = new Date(date);
  var date2 = new Date();
  if (date1 < date2) {
    errors.push({ msg: 'Please enter valid date and time' });
  }

  //check duration
  if (duration < 0) {
    errors.push({ msg: 'Please enter valid duration' });
  }

  if (errors.length > 0) {
    res.render('edit_event', {
      errors,
      name,
      date,
      duration,
      venue,
      description,
    });
  } else {
    //res.send('pass');

    Event.findOne({ _id: id }).then((data) => {
      data.name = name;
      data.date = date;
      data.duration = duration;
      data.venue = venue;
      data.description = description;

      data.save().then((data) => {
        req.flash('success_msg', 'Event Updated');
        res.redirect('/admin/event_dashboard');
      });
    });
    // console.log(newUser);
    // res.send('hello');
  }
});

router.get('/event_dashboard', isAdmin, async (req, res) => {
  const data = await Event.find();
  data.sort((a, b) => {
    return new Date(a.date) - new Date(b.date);
  });
  res.render('event_dashboard', {
    user: req.user,
    events: data,
  });
});

router.get('/feedback', isAdmin, (req, res) => {
  Feedback.find().then((data) => {
    //console.log(data);
    res.render('admin_feedback', {
      user: req.user,
      feedbacks: data,
    });
  });
});

router.post('/feedback', (req, res) => {
  // delete event in database
  //console.log(req.body);
  const { query_id } = req.body;
  //console.log(event_id);
  Feedback.deleteOne({ _id: query_id }).then((data) => {
    //console.log(data);
    res.redirect('/feedback');
  });
});

router.get('/participate/:id', async function (req, res) {
  const event_id = req.params.id;

  //console.log(event_id);

  const data = await Event.find({ _id: event_id }).populate('participants');
  //console.log(data);
  res.render('participate', {
    event_name: data[0].name,
    participants: data[0].participants,
    user_name: req.user.name,
  });
});

router.post('/delete_event', (req, res) => {
  // delete event in database
  //console.log(req.body);
  const { event_id } = req.body;
  //console.log(event_id);
  Event.deleteOne({ _id: event_id }).then((data) => {
    //console.log(data);
    res.redirect('/admin/event_dashboard');
  });
});

router.get('/add_admin', isAdmin, (req, res) =>
  res.render('add_admin', { user: req.user })
);

router.get('/delete_admin', isAdmin, (req, res) =>
  res.render('delete_admin', { user: req.user })
);

//adminlogout
router.get('/logout', (req, res) => {
  req.logout(function (err) {
    req.flash('success_msg', 'You are logged out');
    res.redirect('/admin/');
  });
});

// Add Admin
router.post('/add_admin', (req, res) => {
  //console.log(req.body);
  // res.send('hello');
  const { email } = req.body;
  let errors = [];

  //console.log(programe);
  //check required fields
  if (!email) {
    errors.push({ msg: 'Please enter all fields' });
  }

  //check email id of daiict
  if (
    email.substr(-13, 13) != '@daiict.ac.in' ||
    email[1] != '0' ||
    email[0] != '2' ||
    !(email[4] == '0' || email[4] == '1' || email[4] == '2') ||
    !(
      email[5] == '0' ||
      email[5] == '1' ||
      email[5] == '2' ||
      email[5] == '3' ||
      email[5] == '8'
    ) ||
    email[6] >= '6'
  ) {
    errors.push({ msg: 'Please Register using correct daiict Id' });
  }

  if (errors.length > 0) {
    res.render('add_admin', {
      errors,
    });
  } else {
    //res.send('pass');
    User.findOne({ email: email }).then((user) => {
      if (user) {
        try {
          change = async (req, res) => {
            await User.updateOne(
              {
                _id: user.id,
              },
              {
                $set: {
                  isadmin: true,
                  ismember: true,
                },
              }
            );
          };
          change();

          res.redirect('/admin/dashboard');
        } catch (error) {
          console.log(error);
          //res.send('Not verified');
          res.json({ status: 'Something went wrong' });
        }
      } else {
        errors.push({ msg: 'Email not exists' });
        res.render('add_admin', {
          errors,
        });
      }
    });
  }
});

router.post('/delete_admin', (req, res) => {
  //console.log(req.body);
  // res.send('hello');
  const { email } = req.body;
  let errors = [];

  //console.log(programe);
  //check required fields
  if (!email) {
    errors.push({ msg: 'Please enter all fields' });
  }

  //check email id of daiict
  if (
    email.substr(-13, 13) != '@daiict.ac.in' ||
    email[1] != '0' ||
    email[0] != '2' ||
    !(email[4] == '0' || email[4] == '1' || email[4] == '2') ||
    !(
      email[5] == '0' ||
      email[5] == '1' ||
      email[5] == '2' ||
      email[5] == '3' ||
      email[5] == '8'
    ) ||
    email[6] >= '6'
  ) {
    errors.push({ msg: 'Please Register using correct daiict Id' });
  }

  if (errors.length > 0) {
    res.render('delete_admin', {
      errors,
    });
  } else {
    //res.send('pass');
    User.findOne({ email: email }).then((user) => {
      if (user) {
        try {
          change = async (req, res) => {
            await User.updateOne(
              {
                _id: user.id,
              },
              {
                $set: {
                  isadmin: false,
                  ismember: false,
                },
              }
            );
          };
          change();

          res.redirect('/admin/dashboard');
        } catch (error) {
          console.log(error);
          //res.send('Not verified');
          res.json({ status: 'Something went wrong' });
        }
      } else {
        errors.push({ msg: 'Email not exists' });
        res.render('delete_admin', {
          errors,
        });
      }
    });
  }
});

router.post('/delete_user', (req, res) => {
  const { user_id } = req.body;

  //delete user
  User.deleteOne({ _id: user_id }).then((data) => {
    //console.log(data);
    res.redirect('/admin/user');
  });
});

// Add Event
router.post('/event', (req, res) => {
  const { name, date, duration, venue, description } = req.body;
  let errors = [];

  if (!name || !date || !duration || !venue) {
    errors.push({ msg: 'Please enter all fields' });
  }

  //check date and time
  var date1 = new Date(date);
  var date2 = new Date();
  if (date1 < date2) {
    errors.push({ msg: 'Please enter valid date and time' });
  }

  //check duration
  if (duration < 0) {
    errors.push({ msg: 'Please enter valid duration' });
  }

  if (errors.length > 0) {
    res.render('manage_event', {
      errors,
      name,
      date,
      duration,
      venue,
      description,
    });
  } else {
    const newEvent = new Event({
      name,
      date,
      duration,
      venue,
      description,
    });

    newEvent
      .save()
      .then((event) => {
        req.flash('success_msg', 'Event added successfully');
        res.redirect('/admin/event');
      })
      .catch((err) => console.log(err));
  }
});

module.exports = router;
