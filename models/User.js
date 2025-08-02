const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  isSubscribed: { type: Boolean, default: false },
  subscriptionEndDate: { type: Date }, // New: To store the subscription end date
  stripeCustomerId: { type: String }    // New: To store the Stripe Customer ID
}, { timestamps: true }); // Added timestamps for created/updated dates

module.exports = mongoose.model('User', UserSchema); 