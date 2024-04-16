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


// Import Vehicle model
const Vehicle = require('./models/vehicle'); // Import the Vehicle model

const Contact = require('./models/contactModel');


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




app.post('/api/vehicle/register', cors(), (req, res, next) => {
    upload(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            return res.status(500).json({ message: 'Multer error: ' + err.message });
        } else if (err) {
            return res.status(500).json({ message: 'Unknown error: ' + err.message });
        }
        next();
    });
}, async (req, res) => {
    try {
        const {
            ownerName,
            ownerContact,
            ownerEmail,
            ownerCity,
            vehicleType,
            brand,
            model,
            variant,
            location,
            batteryPower,
            vehicleDescription
        } = req.body;

        if (!req.files || !req.files['interiorImages'] || !req.files['frontImages'] || !req.files['sideImages'] || !req.files['backImages']) {
            return res.status(400).json({ message: 'Image files are missing' });
        }

        const interiorImages = req.files['interiorImages'].map(file => file.path);
        const frontImages = req.files['frontImages'].map(file => file.path);
        const sideImages = req.files['sideImages'].map(file => file.path);
        const backImages = req.files['backImages'].map(file => file.path);

        const color = req.body.color || null;

        const rtoCode = (!['edrone', 'ecycle'].includes(vehicleType)) ? req.body.rtoCode : null;
        const kilometresDriven = (!['edrone', 'ecycle'].includes(vehicleType)) ? req.body.kilometresDriven : null;

        const registrationYear = req.body.registrationYear || null;

        const bodyType = (vehicleType === 'ecar') ? req.body.bodyType : ((vehicleType === 'etractor') ? null : req.body.bodyType);

        const transmissionType = (['ecar', 'eauto', 'ebike'].includes(vehicleType)) ? req.body.transmissionType : ((vehicleType === 'etractor') ? null : req.body.transmissionType);
        

        const price = req.body.price || null;

        if (
            !ownerName ||
            !ownerContact ||
            !ownerEmail ||
            !ownerCity ||
            !vehicleType ||
            !brand ||
            !model ||
            !variant ||
            !location ||
            !batteryPower ||
            !vehicleDescription ||
            !color ||
            !registrationYear ||
            (!['edrone', 'ecycle'].includes(vehicleType) && (!rtoCode || !kilometresDriven)) ||
            ((['ecar', 'eauto', 'ebike'].includes(vehicleType)) && !transmissionType) ||
            (vehicleType === 'ecar' && !bodyType) ||
            (vehicleType === 'etractor' && (bodyType !== null || transmissionType !== null)) ||
            !interiorImages.length ||
            !frontImages.length ||
            !sideImages.length ||
            !backImages.length ||
            !price ||
            !price.currency ||
            !price.value
        ) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        

        const priceWithoutCommas = parseFloat(price.value.replace(/,/g, ''));

        const newVehicle = new Vehicle({
            ownerName,
            ownerContact,
            ownerEmail,
            ownerCity,
            vehicleType,
            brand,
            model,
            variant,
            location,
            rtoCode,
            batteryPower,
            kilometresDriven,
            bodyType,
            color,
            registrationYear,
            vehicleDescription,
            transmissionType,
            interiorImages,
            frontImages,
            sideImages,
            backImages,
            price: {
                currency: price.currency,
                value: priceWithoutCommas
            }
        });

        await newVehicle.save();
        res.status(201).json({ message: 'Vehicle registered successfully' });
    } catch (error) {
        console.error('Vehicle Registration Error:', error);
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});




app.get('/api/vehicles/ecar', async (req, res) => {
    try {
        // Extract filter parameters from request query
        const { brand, location, transmissionType, color, kilometresDriven, price, filterBodyType } = req.query;

        // Construct query based on filter parameters
        let query = { vehicleType: 'ecar' };
        if (brand) query.brand = brand;
        if (location) query.location = location;
        if (transmissionType) query.transmissionType = transmissionType;
        if (color) query.color = color;
        if (kilometresDriven) query.kilometresDriven = { $lte: parseInt(kilometresDriven) };
        if (price) {
            // Split price range from the query string
            const [minPrice, maxPrice] = price.split('-').map(p => parseInt(p.replace(/\D/g, ''))); // Remove non-numeric characters
            if (!isNaN(minPrice) || !isNaN(maxPrice)) {
                query['price.value'] = {}; // Initialize price.value object if it doesn't exist
                if (!isNaN(minPrice)) query['price.value'].$gte = minPrice;
                if (!isNaN(maxPrice)) query['price.value'].$lte = maxPrice;
            }
        }
        if (filterBodyType) query.bodyType = filterBodyType;

        // Query database with filters
        const ecars = await Vehicle.find(query);

        // Convert images to Base64 strings
        const ecarsWithBase64 = ecars.map((ecar) => {
            const frontImagesBase64 = ecar.frontImages.map((imagePath) => {
                const image = fs.readFileSync(imagePath);
                return Buffer.from(image).toString('base64');
            });

            // Repeat the process for other image fields (sideImages, backImages, etc.)

            return { ...ecar._doc, frontImagesBase64 /*, otherImageFields */ };
        });

        // Return filtered results with Base64 encoded images
        res.json(ecarsWithBase64);
    } catch (error) {
        console.error('Error fetching filtered eCar vehicles:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



// Endpoint to fetch ebike details
app.get('/api/vehicles/ebike', async (req, res) => {
    try {
        // Find all ebike vehicles in the database
        const ebikes = await Vehicle.find({ vehicleType: 'ebike' });

        // If no ebikes found, return error
        if (!ebikes || ebikes.length === 0) {
            return res.status(404).json({ message: 'No ebike vehicles found' });
        }

        // Convert images to Base64 strings
        const ebikesWithBase64 = ebikes.map((ebike) => {
            const frontImagesBase64 = ebike.frontImages.map((imagePath) => {
                const image = fs.readFileSync(imagePath);
                return Buffer.from(image).toString('base64');
            });

            // Repeat the process for other image fields (sideImages, backImages, etc.)

            return { ...ebike._doc, frontImagesBase64 /*, otherImageFields */ };
        });

        // If ebikes found, return the details with Base64 images
        res.status(200).json(ebikesWithBase64);
    } catch (error) {
        console.error('Error fetching ebikes:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});


// Endpoint to fetch ecycle details
app.get('/api/vehicles/ecycle', async (req, res) => {
    try {
        // Find all ecycle vehicles in the database
        const ecycles = await Vehicle.find({ vehicleType: 'ecycle' });

        // If no ecycles found, return error
        if (!ecycles || ecycles.length === 0) {
            return res.status(404).json({ message: 'No ecycle vehicles found' });
        }
        // Convert images to Base64 strings
        const ecyclesWithBase64 = ecycles.map((ecycle) => {
            const frontImagesBase64 = ecycle.frontImages.map((imagePath) => {
                const image = fs.readFileSync(imagePath);
                return Buffer.from(image).toString('base64');
            });

            // Repeat the process for other image fields (sideImages, backImages, etc.)

            return { ...ecycle._doc, frontImagesBase64 /*, otherImageFields */ };
        });

        // If ecycles found, return the details
        res.status(200).json(ecyclesWithBase64);
    } catch (error) {
        console.error('Error fetching ecycles:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});


// Endpoint to fetch edrone details
app.get('/api/vehicles/edrone', async (req, res) => {
    try {
        // Find all edrone vehicles in the database
        const edrones = await Vehicle.find({ vehicleType: 'edrone' });

        // If no edrones found, return error
        if (!edrones || edrones.length === 0) {
            return res.status(404).json({ message: 'No edrone vehicles found' });
        }

        // Convert images to Base64 strings
        const edronesWithBase64 = edrones.map((edrone) => {
            const frontImagesBase64 = edrone.frontImages.map((imagePath) => {
                const image = fs.readFileSync(imagePath);
                return Buffer.from(image).toString('base64');
            });

            // Repeat the process for other image fields (sideImages, backImages, etc.)

            return { ...edrone._doc, frontImagesBase64 /*, otherImageFields */ };
        });

        // If edrones found, return the details
        res.status(200).json(edronesWithBase64);
    } catch (error) {
        console.error('Error fetching edrones:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// Endpoint to fetch etractor details
app.get('/api/vehicles/etractor', async (req, res) => {
    try {
        // Find all etractor vehicles in the database
        const etractors = await Vehicle.find({ vehicleType: 'etractor' });

        // If no etractors found, return error
        if (!etractors || etractors.length === 0) {
            return res.status(404).json({ message: 'No etractor vehicles found' });
        }

        // Convert images to Base64 strings
        const etractorsWithBase64 = etractors.map((tractor) => {
            const frontImagesBase64 = tractor.frontImages.map((imagePath) => {
                const image = fs.readFileSync(imagePath);
                return Buffer.from(image).toString('base64');
            });

            // Repeat the process for other image fields (sideImages, backImages, etc.)

            return { ...tractor._doc, frontImagesBase64 /*, otherImageFields */ };
        });

        // If etractors found, return the details
        res.status(200).json(etractorsWithBase64);
    } catch (error) {
        console.error('Error fetching etractors:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});
// Endpoint to fetch eauto details
app.get('/api/vehicles/eauto', async (req, res) => {
    try {
        // Find all eauto vehicles in the database
        const eautos = await Vehicle.find({ vehicleType: 'eauto' });

        // If no eautos found, return error
        if (!eautos || eautos.length === 0) {
            return res.status(404).json({ message: 'No eauto vehicles found' });
        }

        // Convert images to Base64 strings
        const eautosWithBase64 = eautos.map((eauto) => {
            const frontImagesBase64 = eauto.frontImages.map((imagePath) => {
                const image = fs.readFileSync(imagePath);
                return Buffer.from(image).toString('base64');
            });

            // Repeat the process for other image fields (sideImages, backImages, etc.)

            return { ...eauto._doc, frontImagesBase64 /*, otherImageFields */ };
        });

        // Send the response with eauto details including Base64 images
        res.status(200).json(eautosWithBase64);
    } catch (error) {
        console.error('Error fetching eauto vehicles:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});



// Contact form submission endpoint
app.post('/api/contact', async (req, res) => {
    try {
        // Extract data from the request body
        const { name, email, subject, comments } = req.body;

        // Create a new Contact document
        const newContact = new Contact({
            name,
            email,
            subject,
            comments
        });

        // Save the new Contact document to the database
        await newContact.save();

        // Send a success response to the client
        res.status(200).json({ message: 'Message received successfully!' });
    } catch (error) {
        console.error('Error processing contact form:', error);
        // Send an error response to the client
        res.status(500).json({ message: 'Server Error' });
    }
});


// Endpoint to fetch vehicle details by ID
app.get('/api/vehicle/:id', async (req, res) => {
    try {
        const vehicleId = req.params.id;

        // Find the vehicle by ID in the database
        const vehicle = await Vehicle.findById(vehicleId);

        // If vehicle not found, return error
        if (!vehicle) {
            return res.status(404).json({ message: 'Vehicle not found' });
        }

        // If vehicle found, return the details
        res.status(200).json(vehicle);
    } catch (error) {
        console.error('Error fetching vehicle details:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// Generate reset token
function generateResetToken() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// Function to send reset password email
async function sendResetPasswordEmail(email, resetToken) {
    try {
        // Email options
        const mailOptions = {
            from: 'tanmayrp97@gmail.com', // Your Gmail email address
            to: email,
            subject: 'Reset Your Password',
            html: `<p>Hello,</p><p>You have requested to reset your password. Please click the following link to reset your password:</p><p><a href="http://localhost:3000/reset-password?token=${resetToken}">Reset Password</a></p><p>If you did not request this, please ignore this email.</p>`
        };

        // Send email
        await transporter.sendMail(mailOptions);
        console.log('Reset password email sent to', email);
    } catch (error) {
        console.error('Error sending reset password email:', error);
    }
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