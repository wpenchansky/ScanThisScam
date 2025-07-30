const { MongoClient } = require('mongodb');
const mongoose = require('mongoose'); // New: Import mongoose
require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/scamdetection'; // Default URI
const DB_NAME = 'scamdetection'; // Your database name

async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI, { // Use mongoose to connect
      useNewUrlParser: true,
      useUnifiedTopology: true,
      dbName: DB_NAME, // Specify the database name here for Mongoose
    });
    console.log('Connected to MongoDB successfully with Mongoose!');
    return mongoose.connection.db; // Return the underlying MongoDB client db object
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1); // Exit process if connection fails
  }
}

module.exports = connectDB;
