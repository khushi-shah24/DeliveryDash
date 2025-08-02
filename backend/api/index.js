// File: index.js
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// --- Mongoose Configuration for Serverless ---
// Set strictQuery to true to suppress the deprecation warning
mongoose.set('strictQuery', true);

// Cache the database connection
let cachedDb = null;

/**
 * Connects to MongoDB, reusing an existing connection if available.
 * This pattern is crucial for serverless environments to avoid
 * creating new connections on every function invocation.
 */
async function connectToDatabase() {
    // If a connection is already established, return it
    if (cachedDb && mongoose.connection.readyState === 1) { // readyState 1 means connected
        console.log('Using existing MongoDB connection');
        return cachedDb;
    }

    // If no connection or connection is not ready, establish a new one
    console.log('Establishing new MongoDB connection');
    try {
        const client = await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            // Add server selection timeout to prevent indefinite waiting
            serverSelectionTimeoutMS: 5000, // Keep trying for 5 seconds
            // Keep alive for long-running operations (optional, but good for serverless)
            // This helps prevent connections from being closed by the database due to inactivity
            // while the function instance is still warm.
            keepAlive: true,
            keepAliveInitialDelay: 300000 // 5 minutes
        });
        cachedDb = client.connection.db;
        console.log('MongoDB connected successfully');
        return cachedDb;
    } catch (err) {
        console.error('MongoDB connection error:', err);
        throw new Error('Failed to connect to MongoDB'); // Re-throw to propagate the error
    }
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
    // Ensure database connection before handling the request
    try {
        await connectToDatabase();
    } catch (error) {
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
            if (err) throw err;
            res.json({ token, email: user.email });
        });
    } catch (e) {
        console.error(e.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
app.post('/api/auth/login', async (req, res) => {
    // Ensure database connection before handling the request
    try {
        await connectToDatabase();
    } catch (error) {
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
            if (err) throw err;
            res.json({ token, email: user.email });
        });
    } catch (e) {
        console.error(e.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/deliveries/quote
// @desc    Get live quotes from "courier partners"
// @access  Private
app.post('/api/deliveries/quote', authMiddleware, async (req, res) => {
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
    // Ensure database connection before handling the request
    try {
        await connectToDatabase();
    } catch (error) {
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
        console.error(e.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/deliveries/status/:id
// @desc    Get live status of a delivery
// @access  Private
app.get('/api/deliveries/status/:id', authMiddleware, async (req, res) => {
    // Ensure database connection before handling the request
    try {
        await connectToDatabase();
    } catch (error) {
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
        console.error(e.message);
        res.status(500).send('Server Error');
    }
});

// Export the app for Vercel to use as a serverless function
module.exports = app;
