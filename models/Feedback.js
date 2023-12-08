const mongoose = require('mongoose');
const conn_k = require('../db/connectdb.js').connectdb_k;
const FeedbackSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now,
  },
  feedback: {
    type: String,
    required: true,
  },
});

const Feedback = conn_k.model('Feedback', FeedbackSchema);

module.exports = Feedback;
