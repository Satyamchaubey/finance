const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    description: String,
    type: { type: String, enum: ['Expense', 'Income'] },
    date: Date,
    amount: Number
});


const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, unique: true },
    password: String,
    googleId: {
        type: String,
        unique: true,
        sparse: true, // Allows multiple null values in unique fields
    },
    transactions: Array,
    profilePicture: { type: String }, // Add this field
    passwordResetToken: String, // Token for password reset functionality
    passwordResetExpires: Date // Expiration time for the token
  });
  

module.exports = mongoose.model('User', userSchema);
