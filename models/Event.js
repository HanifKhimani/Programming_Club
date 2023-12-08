const mongoose = require('mongoose');
const conn_k = require('../db/connectdb.js').connectdb_k;
const EventSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  date: {
    type: Date,
    required: true,
  },
  duration: {
    type: Number,
    required: true,
  },
  venue: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  participants: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  ],
});

const Event = conn_k.model('Event', EventSchema);

module.exports = Event;
