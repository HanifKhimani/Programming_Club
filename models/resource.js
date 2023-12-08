// export mongoose model
const mongoose = require('mongoose');
const conn = require('../db/connectdb.js').connectdb;

const ResourceSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: [100, 'resource title cannot exceed 100 characters'],
    },
    description: {
      type: String,
      required: true,
      maxlength: [5000, 'resource description cannot exceed 5000 characters'],
    },
    link: {
      type: String,
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

//const resourcedb = mongoose.model('ResourceSchema', ResourceSchema);
const resourcedb = conn.model('ResourceSchema', ResourceSchema);

module.exports = resourcedb;
