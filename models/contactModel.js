// contactModel.js

const mongoose = require('mongoose');

// Define the schema for the Contact data
const contactSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    comments: { type: String, required: true }
});

// Create a model from the schema
const Contact = mongoose.model('Contact', contactSchema);

module.exports = Contact;
