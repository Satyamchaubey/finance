const mongoose = require('mongoose');

// Transaction Schema
const transactionSchema = new mongoose.Schema({
    description: { type: String, required: true },
    type: { type: String, enum: ['Expense', 'Income'], required: true },
    date: { type: Date, required: true },
    amount: { type: Number, required: true }
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, unique: true },
    password: String,
    googleId: {
        type: String,
        unique: true,
        sparse: true, // Allows multiple null values in unique fields
    },
    transactions: [transactionSchema], // Store transactions as an array of transaction documents
    profilePicture: { type: String }, // Add this field
    passwordResetToken: String, // Token for password reset functionality
    passwordResetExpires: Date, // Expiration time for the token
    otp: { type: String },          // Field for OTP
    otpExpiration: { type: Date },  // Expiration time for OTP
});

module.exports = mongoose.model('User', userSchema);
