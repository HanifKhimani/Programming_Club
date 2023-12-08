const mongoose = require('mongoose');

const connectdb = mongoose.createConnection(process.env.MongoURI);
const connectdb_k = mongoose.createConnection(process.env.MongoURI);
module.exports = { connectdb, connectdb_k };
