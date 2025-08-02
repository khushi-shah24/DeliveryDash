// File: index.js
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config(); // Loads .env file for local development

const app = express();
app.use(express.json());
app.use(cors());

// --- Mongoose Configuration for Serverless ---
// Set strictQuery to true to suppress the deprecation warning
mongoose.set('strictQuery', true);

// Increase the Mongoose operation timeout. This is a buffer,
// not a solution for underlying connection issues, but can help
// prevent premature timeouts if the database is slow to respond.
mongoose.set('bufferTimeoutMS', 30000); // Set to 30 seconds

// Cache the database connection promise to avoid multiple connection attempts
// during a single cold start or warm instance lifecycle.
let cachedDbConnection = null;

/**
 * Connects to MongoDB, reusing an existing connection if available.
 * This pattern is crucial for serverless environments to avoid
 * creating new connections on every function invocation and to handle
 * connection drops gracefully.
 */
async function connectToDatabase() {
    // If a connection promise already exists and is resolving, return it
    if (cachedDbConnection) {
        console.log('Using existing MongoDB connection promise.');
        return cachedDbConnection;
    }

    // Check if there's an existing connection and if it's healthy.
    // readyState 1 means connected, 2 means connecting, 3 means disconnecting, 0 means disconnected.
    // We only want to reuse if it's actively connected.
    if (mongoose.connections && mongoose.connections[0] && mongoose.connections[0].readyState === 1) {
        console.log('Reusing active MongoDB connection.');
        cachedDbConnection = Promise.resolve(mongoose.connections[0].db); // Wrap in a promise for consistency
        return cachedDbConnection;
    }

    console.log('Establishing new MongoDB connection...');
    // Create a new connection promise
    cachedDbConnection = mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 10000, // Try to connect for 10 seconds
        socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
        connectTimeoutMS: 10000, // Give up initial connection after 10 seconds
        // keepAlive is deprecated in newer Mongoose versions, but if using older,
        // it helps prevent connections from being closed by the database due to inactivity
        // while the function instance is still warm.
        // If your Mongoose version is 6.x or higher, this might not be needed or could be removed.
        // keepAlive: true,
        // keepAliveInitialDelay: 300000 // 5 minutes
    })
    .then(client => {
        console.log('MongoDB connected successfully!');
        return client.connection.db;
    })
    .catch(err => {
        console.error('MongoDB connection error:', err.message);
        cachedDbConnection = null; // Clear the cached promise on failure
        throw new Error('Failed to connect to MongoDB: ' + err.message);
    });

    return cachedDbConnection;
}

// --- Models ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    pickupLocation: { type: String, required: true },
    dropoffLocation: { type: String, required: true },
    packageDetails: { type: String, required: true },
    courier: { type: String, required: true },
    status: { type: String, default: 'Pending Pickup' },
    liveTrackingId: { type: String } // To simulate external tracking
}, { timestamps: true });
const Order = mongoose.model('Order', orderSchema);

// --- JWT Middleware ---
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (e) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// --- Routes ---

// @route   POST /api/auth/register
// @desc    Register a new user
app.post('/api/auth/register', async (req, res) => {
    try {
        await connectToDatabase(); // Ensure DB connection
    } catch (error) {
        console.error('API /register - DB connection failed:', error);
        return res.status(500).send('Database connection error');
    }

    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        user = new User({ email, password: hashedPassword });
        await user.save();
        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) {
                console.error('JWT signing error:', err);
                return res.status(500).send('Server Error during token generation');
            }
            res.json({ token, email: user.email });
        });
    } catch (e) {
        console.error('API /register - Server Error:', e.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
app.post('/api/auth/login', async (req, res) => {
    try {
        await connectToDatabase(); // Ensure DB connection
    } catch (error) {
        console.error('API /login - DB connection failed:', error);
        return res.status(500).send('Database connection error');
    }

    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) {
                console.error('JWT signing error:', err);
                return res.status(500).send('Server Error during token generation');
            }
            res.json({ token, email: user.email });
        });
    } catch (e) {
        console.error('API /login - Server Error:', e.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/deliveries/quote
// @desc    Get live quotes from "courier partners"
// @access  Private
app.post('/api/deliveries/quote', authMiddleware, (req, res) => {
    // No database interaction needed for mock quotes, so no connectToDatabase call here.
    const mockQuotes = [
        { courier: 'FlashExpress', price: 15, eta: '2 hours', id: 'FLSH' + Math.floor(Math.random() * 10000) },
        { courier: 'QuickShip', price: 22, eta: '1.5 hours', id: 'QSHP' + Math.floor(Math.random() * 10000) },
        { courier: 'ReliableGo', price: 18, eta: '3 hours', id: 'RLGO' + Math.floor(Math.random() * 10000) }
    ];
    res.json(mockQuotes);
});

// @route   POST /api/deliveries/book
// @desc    Book a new delivery
// @access  Private
app.post('/api/deliveries/book', authMiddleware, async (req, res) => {
    try {
        await connectToDatabase(); // Ensure DB connection
    } catch (error) {
        console.error('API /book - DB connection failed:', error);
        return res.status(500).send('Database connection error');
    }

    const { pickupLocation, dropoffLocation, packageDetails, courier, liveTrackingId } = req.body;
    try {
        const newOrder = new Order({
            userId: req.user.id,
            pickupLocation,
            dropoffLocation,
            packageDetails,
            courier,
            liveTrackingId
        });
        await newOrder.save();
        res.status(201).json(newOrder);
    } catch (e) {
        console.error('API /book - Server Error:', e.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/deliveries/status/:id
// @desc    Get live status of a delivery
// @access  Private
app.get('/api/deliveries/status/:id', authMiddleware, async (req, res) => {
    try {
        await connectToDatabase(); // Ensure DB connection
    } catch (error) {
        console.error('API /status - DB connection failed:', error);
        return res.status(500).send('Database connection error');
    }

    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ msg: 'Order not found' });
        }
        // Simplified status logic for the MVP
        const statuses = ['Pending Pickup', 'In Transit', 'Delivered'];
        const randomStatusIndex = Math.floor(Math.random() * statuses.length);
        order.status = statuses[randomStatusIndex];
        // Note: In a real app, you might save the updated status to the DB
        // await order.save();
        res.json({ orderId: order._id, status: order.status, lastUpdated: new Date() });
    } catch (e) {
        console.error('API /status - Server Error:', e.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/deliveries/estimate-price
// @desc    Get estimated freight price from Delhivery API
// @access  Private
app.post('/api/deliveries/estimate-price', authMiddleware, async (req, res) => {
    // Delhivery API URL for bulk rate calculator
    const delhiveryApiUrl = 'https://ucp-app-gateway.delhivery.com/web/api/wallet/bulk_rate_calculator';

    // The request body for this API expects an array of 'requestss'
    const { requests } = req.body;

    // Validate essential inputs: 'requests' array must exist and not be empty
    if (!requests || !Array.isArray(requests) || requests.length === 0) {
        return res.status(400).json({ msg: 'Missing or invalid "requests" array in body for price estimation.' });
    }

    // You might want to add more granular validation for each item in the 'requests' array
    // For example, checking for 'origin_pin', 'destination_pin', 'weight', etc.
    // For now, we'll assume the incoming 'requests' array contains valid objects.

    try {
        // The Delhivery API expects the payload directly under the 'requests' key
        const delhiveryRequestBody = {
            requests: requests.map(item => ({
                packaging_type: item.packaging_type || 'FLYER',
                shipment_type: item.shipment_type || 'FORWARD',
                origin_pin: item.origin_pin,
                destination_pin: item.destination_pin,
                weight: item.weight,
                weight_unit: item.weight_unit || 'GM',
                payment_mode: item.payment_mode || 'PREPAID',
                cod_amount: item.cod_amount || 0,
                length: item.length || 1,
                breadth: item.breadth || 1,
                height: item.height || 1,
                shipping_mode: item.shipping_mode || 'SURFACE',
                id: item.id || Math.random().toString(36).substring(2, 15) // Generate a unique ID if not provided
            }))
        };

        // Make the call to the Delhivery API
        const response = await fetch(delhiveryApiUrl, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.DELHIVERY_API_TOKEN}`, // Use environment variable for token
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(delhiveryRequestBody)
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error(`Delhivery API error: ${response.status} - ${errorText}`);
            return res.status(response.status).json({ msg: 'Failed to get price estimate from Delhivery', details: errorText });
        }

        const data = await response.json();
        res.json(data); // Send the Delhivery response directly to the cliet

    } catch (error) {
        console.error('Error calling Delhivery API:', error.message);
        res.status(500).send('Server Error: Could not get price estimate.');
    }
});



// Export the app for Vercel to use as a serverless function
module.exports = app;
