const express = require('express');
const router = express.Router();
router.use(express.static('public'));
const { ensureAuthenticated } = require('../config/auth');

var bodyParser = require('body-parser');
// parse various different custom JSON types as JSON
router.use(bodyParser.json({ type: 'application/json' }));

//Load User model
const User = require('../models/User');
const Event = require('../models/Event');
const Feedback = require('../models/Feedback');

// Welcome Page
router.get('/', (req, res) => res.render('welcome'));

// Dashboard

router.get(
  '/dashboard',
  ensureAuthenticated,
  (req, res) =>
    res.render('dashboard', {
      user: req.user,
    })
  //console.log(req.user)
);

//Profile
router.get(
  '/profile',
  ensureAuthenticated,
  (req, res) =>
    res.render('profile.ejs', {
      user: req.user,
    })
  //console.log(req.user.name)
);

router.get(
  '/feedback',
  ensureAuthenticated,
  (req, res) =>
    res.render('user_feedback', {
      user: req.user,
    })
  //console.log(req.user.name)
);

router.post('/feedback', function (req, res) {
  const { title, feedback } = req.body;
  const email = req.user.email;
  const name = req.user.name;

  //console.log(email, title, name, feedback);

  let errors = [];

  if (!title || !feedback) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (errors.length > 0) {
    res.render('user_feedback', {
      errors,
      title,
      feedback,
    });
  } else {
    const newFeedback = new Feedback({
      title,
      email,
      name,
      feedback,
    });
    newFeedback.save().then((feedback) => {
      req.flash('success_msg', 'Your feedback has been submitted');
      res.redirect('/feedback');
    });
  }
});

router.get('/event', ensureAuthenticated, function (req, res) {
  Event.find().then((data) => {
    //console.log(data);
    res.render('event.ejs', {
      user: req.user,
      practices: data,
    });
  });
  //console.log(req.user.name)
});

router.post('/event', function (req, res) {
  //console.log(req.body.event_id);
  const event_id = req.body.event_id;
  const user_id = req.body.user_id;

  Event.findOne({ _id: event_id }).then((event) => {
    if (event.participants.includes(user_id)) {
      // alert('You have already registered for this event');
      //res.send(201);
    } else {
      updatedEvent = async (req, res) => {
        await Event.findByIdAndUpdate(
          event_id,
          {
            $push: { participants: user_id },
          },
          {
            new: true,
          }
        );
      };
      updatedEvent();
    }
  });
});

router.post('/event/deregister', function (req, res) {
  //console.log(req.body.event_id);
  const event_id = req.body.event_id;
  const user_id = req.body.user_id;

  let participantsexist = true;

  Event.findOne({ _id: event_id }).then((event) => {
    if (event.participants.includes(user_id)) {
      Event.findByIdAndUpdate(
        event_id,
        {
          $pull: { participants: user_id },
        },
        {
          new: true, // Return the updated event object
        }
      );
    } else {
      participantsexist = false;
    }
  });

  if (participantsexist == 0) {
    req.flash('error_msg', 'You have not registered for this event');
    res.redirect('/event');
  } else {
    req.flash(
      'success_msg',
      'You have successfully deregistered for the event'
    );
    res.redirect('/event');
  }
});

//edit Profile
router.get(
  '/edit_profile',
  ensureAuthenticated,
  (req, res) =>
    res.render('edit_profile.ejs', {
      user: req.user,
    })
  //console.log(req.user.name)
);

router.post('/edit_profile', (req, res) => {
  console.log(req.body);
  // res.send('hello');
  const { name, programe, batch, cfprofile, address } = req.body;
  const email = req.user.email;

  User.findOne({ email: email }).then((user) => {
    //console.log(user);
    try {
      change = async (req, res) => {
        await User.updateOne(
          {
            _id: user.id,
          },
          {
            $set: {
              name: name,
              programe: programe,
              batch: batch,
              cfprofile: cfprofile,
              address: address,
            },
          }
        );
      };
      change();

      res.redirect('/profile');
    } catch (error) {
      console.log(error);
      //res.send('Not verified');
      res.json({ status: 'Something went wrong' });
    }
  });
});

module.exports = router;
