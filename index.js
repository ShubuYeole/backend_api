// server.js

// Install CORS to solve the issue for cross-site to fetch the data: middleware concept

// adding express for the session management for ID And data for the admin session management 

// Adding SSL for HTTPS 
const http = require('http');
const https = require('https');
const multer = require('multer'); // require to save the images
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const express = require('express');
const mongoose = require('mongoose');
//const { ObjectId } = require('mongodb');
const { ObjectId } = require('mongoose').Types;
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session); // used to store the session in mongodb
const { v4: uuidv4 } = require('uuid'); // using UUid to genrate the session id in uuid
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;




// model to store the user managment session info 
// Create a new MongoDBStore instance
const store = new MongoDBStore({
  uri: 'mongodb://51.79.225.217:27017/dev',
  collection: 'sessions',
});

// Catch errors if there are any while storeing the data in the mongodb database
store.on('error', function (error) {
  console.error('Session store error:', error);
});


app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*")
  next()
})


// Use cookie-parser middleware
app.use(cookieParser());
// Middleware
app.use(express.json());
app.use(cors());
// implementing the session logic here. 

app.use(session({
  secret: 'shubuyeole', // secret string used to sign the session id cookie
  resave: false,  // don't save session id unmodified; default value is false
  saveUninitialized: false, // session will not be created if there is nothing to store; default value will be false
  store: store,
  cookie: { maxAge: 1000 * 60 * 60 * 24, secure: true, samesite: 'none', httpOnly: true } // session timeout of 60 seconds  maxAge is for 1 day
}));

// Define an endpoint for serving uploaded images
app.use('/uploads', express.static('uploads'));


// Middleware to check if user is logged in
const requireLogin = (req, res, next) => {
  if (!req.session.isLoggedIn) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// MongoDB Connection
mongoose.connect("mongodb://51.79.225.217:27017/dev")
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));






// User Model
const User = mongoose.model('User', {
  name: { type: String, default: '' },
  email: { type: String },
  password: { type: String },
  customer_address: { type: String, default: '' },
  account_status: { type: String, enum: ['active', 'inactive'], default: 'active' },  //
  mobile_no: { type: String, default: '' },
  account_type: { type: String, enum: ['admin', 'customer', 'guest'], default: 'customer' } //

});

// Model for to store the EV data in the database. 
// Define schema for Electric Vehicle
const electricVehicleSchema = new mongoose.Schema({
  name: { type: String, required: true },
  model: { type: String, required: true },
  type: { type: String, required: true },
  rangeInKm: { type: Number, required: true },
  approved: { type: Boolean, required: true },
  images: [String],
  price: { type: Number, required: true },
  keywords: [String]
});

// Create Electric Vehicle model
const ElectricVehicle = mongoose.model('ElectricVehicle', electricVehicleSchema);



//rent your ev data

// Define a schema for the data
const rentEVSchema = new mongoose.Schema({
  ownerName: String,
  ownerContact: String,
  ownerEmail: String,
  ownerCity: String,
  vehicleType: String,
  brand: String,
  model: String,
  plateNo: String,
  batteryPower: String,
  kilometresDriven: String,
  image: String, // For simplicity, store image URL
  bodyType: String,
  price: String
});

// Define a model based on the schema
const RentEV = mongoose.model('RentEV', rentEVSchema);

// Set up Multer for handling file uploads
//const upload = multer({ dest: 'uploads/' });

// Set up Multer for handling file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Save images to the 'uploads/' directory
  },
  filename: function (req, file, cb) {
    // Set filename to be current timestamp + original file extension
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

// Define file filter function to accept only image files
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true); // Accept the file
  } else {
    cb(new Error('Only image files are allowed'), false); // Reject the file
  }
};

// Set up Multer with storage and file filter
const upload = multer({ storage: storage, fileFilter: fileFilter });





// Another method to use for session-managment.


// Define the schema for the sessions collection
const sessionSchema = new mongoose.Schema({
  session: {
    isLoggedIn: Boolean,
    userId: mongoose.Schema.Types.ObjectId,
    // Add other fields as needed
  }
});

// Create a model for the sessions collection
const Session = mongoose.model('Session', sessionSchema, 'sessions');







// Routes
// Used to create a new user.

app.post('/api/signup', cors(), async (req, res) => {
  try {
    const { name, email, password, account_type, account_status } = req.body;
    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create new user with hashed password
    const newUser = new User({ name, email, password: hashedPassword, account_type: account_type || 'customer', account_status: account_status || 'active' });
    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error signing up:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

//Used by the User to update information.

app.put('/api/user/:userId', cors(), async (req, res) => {
  try {
    const userId = req.params.userId;
    const { name, email, password, account_type, account_status, customer_address, mobile_no } = req.body;

    // Find the user by ID
    let user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user information if provided in request body
    if (name !== undefined) user.name = name;
    if (email !== undefined) user.email = email;
    if (password !== undefined) {
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
    }
    if (account_type !== undefined) user.account_type = account_type;
    if (account_status !== undefined) user.account_status = account_status;
    if (customer_address !== undefined) user.customer_address = customer_address;
    if (mobile_no !== undefined) user.mobile_no = mobile_no;

    // Save the updated user
    await user.save();
    res.status(200).json({ message: 'User information updated successfully' });
  } catch (error) {
    console.error('Error updating user information:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

//Used by the User to Delete his Account.

app.delete('/api/user/:userId', cors(), async (req, res) => {
  try {
    const userId = req.params.userId;

    // Find the user by ID and delete
    const deletedUser = await User.findByIdAndDelete(userId);
    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});





// Login Route
app.post('/api/login', cors(), async (req, res) => {
  try {
    const { email, password } = req.body;
    // Check if user exists with the provided email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    // Check if the password is correct
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    // If email and password are correct, user is authenticated
    req.session.isLoggedIn = true; // for biw disabling the Logged in state
    res.cookie('connect.sid', 'your-session-id', { httpOnly: false });
    //return res.send('cookie has been set!');

    req.session.userId = user._id;;
    //console.log(res.getHeaders());
    res.status(200).json({ message: 'Login successful', userId: user._id });



  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout Route
app.get('/api/logout', cors(), (req, res) => {
  // Destroy session to log out user
  req.session.destroy((err) => {
    if (err) {
      console.error('Error logging out:', err);
      res.status(500).json({ error: 'Server error' });
    } else {
      res.json({ message: 'Logout successful' });
      //req.session.isLoggedIn = false;
    }
  });
});

// Endpoint to check session status
app.get('/api/check-session/:userId', cors(), async (req, res) => {
  try {
    const userId = req.params.userId;

    // Get session ID from the cookie
    const sessionId = req.cookies['connect.sid'];

    // Query the sessions collection in MongoDB to check if the user is logged in
    const session = await Session.findOne({ 'session.userId': userId });


    if (session && session.session.isLoggedIn) {
      // If the user is logged in, send a response with session data
      res.status(200).json({ isLoggedIn: true, userId });
    } else {
      // If the user is not logged in or session doesn't exist, send a response with isLoggedIn as false
      res.status(401).json({ isLoggedIn: false, userId });
    }
  } catch (error) {
    console.error('Error checking session:', error);
    res.status(500).json({ error: 'Server error' });
  }
});



//  using just to check whether the user is logged in or not to check whether the session is working or  not this 
// this will be deleted in the main code.

app.post('/api/data', cors(), requireLogin, [
  body('username').isLength({ min: 5 }).withMessage('Username must be at least 5 characters long'),
  body('password').isStrongPassword().withMessage('Password must be strong'),
], (req, res) => {
  // Handle request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
});

// Define a variable to store EV data
let electricVehicles = [];

// Define a route to add a new electric vehicle
app.post('/api/admin/add_ev', cors(), requireLogin, [
  body('name').notEmpty().withMessage('Name is required'),
  body('model').notEmpty().withMessage('Model is required'),
  body('transmission').notEmpty().withMessage('Transmission is required'),
  body('type').notEmpty().withMessage('Type is required'),
  body('rangeInKm').notEmpty().withMessage('Range in km is required'),
  body('approved').notEmpty().withMessage('Approved status is required'),
  body('images').notEmpty().withMessage('Images are required'),
  body('price').notEmpty().withMessage('Price is required'),
  body('keywords').notEmpty().withMessage('Keywords are required'),
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Extract data from the request body
    const { name, model, transmission, type, rangeInKm, approved, images, price, keywords } = req.body;



    // Create a new EV object
    const newEV = new ElectricVehicle({
      name,
      model,
      transmission,
      type,
      rangeInKm,
      approved,
      images,
      price,
      keywords
    });

    // Save the new EV to the database
    const savedEV = await newEV.save();

    // Return a success message along with the newly created EV data
    res.status(201).json({
      success: true,
      message: 'Electric vehicle added successfully!',
      ev: savedEV
    });
  } catch (error) {
    console.error('Error adding electric vehicle:', error);
    res.status(500).json({ error: 'Server error' });
  }
});



// handel with POST method to save the ev data 

// Define a POST endpoint for handling form submissions
app.post('/api/rentev', cors(), upload.single('image'), async (req, res) => {
  try {
    // Create a new instance of RentEV model with form data
    const newRentEV = new RentEV({
      ownerName: req.body.ownerName,
      ownerContact: req.body.ownerContact,
      ownerEmail: req.body.ownerEmail,
      ownerCity: req.body.ownerCity,
      vehicleType: req.body.vehicleType,
      brand: req.body.brand,
      model: req.body.model,
      plateNo: req.body.plateNo,
      batteryPower: req.body.batteryPower,
      kilometresDriven: req.body.kilometresDriven,
      image: req.file.path, // Save image path
      bodyType: req.body.bodyType,
      price: req.body.price
    });




    // Save the data to MongoDB
    await newRentEV.save();

    res.status(201).json({ message: 'Form data saved successfully' });
  } catch (error) {
    console.error('Error saving form data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// API endpoint for retrieving form data with images
app.get('/api/view/rentev', cors(), async (req, res) => {
  try {
    // Fetch all form data from the database
    const formData = await RentEV.find();

    // Map over the form data to include image URLs
    const formDataWithImages = formData.map(data => ({
      ...data._doc,
      imageUrl: `${req.protocol}://${req.get('host')}/${data.image}`
    }));

    res.status(200).json(formDataWithImages);
  } catch (error) {
    console.error('Error fetching form data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});





// Renterals flow to check for the required time and price accordingly

// Define rental schema and model
const rentalSchema = new mongoose.Schema({
  startDate: Date,
  startTime: String,
  endDate: Date,
  location: String,
  // Add more fields as needed
  price: Number // Add price field to store calculated price
});

const Rental = mongoose.model('Rental', rentalSchema);

// Define API endpoint for creating a new rental
app.post('/api/rentals', cors(), async (req, res) => {
  try {
    // Calculate the price based on rental duration, vehicle type, etc.
    const price = calculatePrice(req.body.startDate, req.body.endDate, req.body.vehicleType);
    
    // Create a new rental object with form data and calculated price
    const newRental = new Rental({
      ...req.body,
      price: price
    });

    // Save the rental data to the database
    await newRental.save();

    res.status(201).json(newRental);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// API endpoint to view submitted rental data
app.get('/api/rentals', cors(), async (req, res) => {
  try {
    // Fetch all rental data from the database
    const rentalData = await Rental.find();
    res.status(200).json(rentalData);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// Function to calculate the price based on rental duration and vehicle type
function calculatePrice(startDate, endDate, vehicleType) {
  // Add your logic to calculate the price here
  // Example: calculate price based on duration and vehicle type
  // For demonstration, let's assume a flat rate of $50 per day for all vehicle types
  const start = new Date(startDate);
  const end = new Date(endDate);
  const durationInDays = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
  const basePricePerDay = 50; // Base price per day for all vehicle types
  const totalPrice = durationInDays * basePricePerDay;

  return totalPrice;
}







// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Server error' });
});


const httpServer = http.createServer(app);

// Start HTTP server
httpServer.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});