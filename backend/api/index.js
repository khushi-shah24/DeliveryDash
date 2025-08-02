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

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

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
app.post('/api/deliveries/quote', authMiddleware, (req, res) => {
    // For a hackathon, we will simulate this.
    // In a real app, we would call external APIs here.
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
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ msg: 'Order not found' });
        }
        // Simplified status logic for the MVP
        const statuses = ['Pending Pickup', 'In Transit', 'Delivered'];
        const randomStatusIndex = Math.floor(Math.random() * statuses.length);
        order.status = statuses[randomStatusIndex];
        res.json({ orderId: order._id, status: order.status, lastUpdated: new Date() });
    } catch (e) {
        console.error(e.message);
        res.status(500).send('Server Error');
    }
});

// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

module.exports = app; // Export the app for testing