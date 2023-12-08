const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const jwt = require('jsonwebtoken');
var nodemailer = require('nodemailer');
router.use(express.static('public'));

const JWT_SECRET =
  'hvdvay6ert72839289()aiyg8t87qt72393293883uhefiuh78ttq3ifi78272jbkj?[]]pou89ywe';

//Load User model
const User = require('../models/User');

// Login Page
router.get('/login', (req, res) => res.render('login'));

// Register Page
router.get('/register', (req, res) => res.render('register'));

// Forgot password page
router.get('/forgot', (req, res) => res.render('forgot'));


function isStrongPassword(password) {
  const minLength = 6; // Minimum length requirement
  const maxLength = 12; // Maximum length requirement
  const hasUpperCase = /[A-Z]/.test(password); // Upper case letters requirement
  const hasLowerCase = /[a-z]/.test(password); // Lower case letters requirement
  const hasNumber = /[0-9]/.test(password); // Numbers requirement
  const hasSpecialChar = /[$&+,:;=?@#|'<>.^*()%!-]/.test(password); // Special characters requirement

  if (password.length < minLength || password.length > maxLength) {
    return false;
  }

  if (!hasUpperCase || !hasLowerCase || !hasNumber || !hasSpecialChar) {
    return false;
  }

  return true;
}

// Register
router.post('/register', (req, res) => {
  const { name, email, programe, batch, password, password2 } = req.body;
  let errors = [];

  var emailcheck = email.substr(6, 3);
  emailcheck = parseInt(emailcheck);

  if (
    !name ||
    !email ||
    !password ||
    !password2 ||
    programe == '0' ||
    batch == '0'
  ) {
    errors.push({ msg: 'Please enter all fields' });
  }

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
    (email[4] == '0' && email[5] == '0') ||
    email[6] >= '6' ||
    !(emailcheck > 0 && emailcheck <= 600)
  ) {
    errors.push({ msg: 'Please Register using correct daiict Id' });
  }

  if (!isStrongPassword(password)) {
    errors.push({
      msg: 'Password must be at least 8 characters long and must contain at least one upper case letter, one lower case letter, one number and one special character',
    });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      programe,
      batch,
      password,
      password2,
    });
  } else {
    User.findOne({ email: email }).then((user) => {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          name,
          email,
          programe,
          batch,
          password,
          password2,
        });
      } else {
        const newUser = new User({
          name,
          email,
          password,
          programe,
          batch,
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then((user) => {
                req.flash(
                  'success_msg',
                  'You are now registered and can log in'
                );
                res.redirect('/users/login');
              })
              .catch((err) => console.log(err));
          });
        });
      }
    });
  }
});


// Login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true,
  })(req, res, next);
});

//logout
router.get('/logout', (req, res) => {
  req.logout(function (err) {
    req.flash('success_msg', 'You are logged out');
    res.redirect('/');
  });
});

//forgot password
router.post('/forgot', async (req, res) => {
  const { email,password } = req.body;

  try {
    if (!email || !password) {
      throw new Error('Please enter all fields');
    }

    const user = await User.findOne({ email });

    if (!user) {
      throw new Error('This email is not registered yet');
    }

    // Check if the password meets the strength criteria
    if (!isStrongPassword(password)) {
      throw new Error('Password must be at least 8 characters long and must contain at least one upper case letter, one lower case letter, one number, and one special character');
    }

    // Update user's password
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.updateOne({ _id: user._id }, { $set: { password: hashedPassword } });

    req.flash('success_msg', 'Password updated successfully');

    const secret = JWT_SECRET + user.password;
    const token = jwt.sign({ email: user.email, id: user._id }, secret, { expiresIn: '5m' });

    // You can redirect
    setTimeout(() => {
      res.redirect('/users/login');
    }, 5000);

  } catch (error) {
    console.error('Forgot Password Error:', error.message);
    res.render('forgot', { errors: [{ msg: error.message }], email });
  }
});

module.exports = router;