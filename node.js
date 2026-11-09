// server.js - Entry point for the Instagram Clone Backend
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/instagram-clone', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

// User Schema & Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profilePic: { type: String, default: '' },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const User = mongoose.model('User', userSchema);

// Post Schema & Model
const postSchema = new mongoose.Schema({
    caption: { type: String },
    image: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{
        text: String,
        author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        createdAt: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

const Post = mongoose.model('Post', postSchema);

// JWT Auth Middleware
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    try {
        const verified = jwt.verify(token.replace('Bearer ', ''), 'SECRET_KEY');
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token.' });
    }
};

// --- AUTH ROUTES ---

// Register User
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id }, 'SECRET_KEY', { expiresIn: '1d' });
        res.json({ token, userId: user._id, username: user.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- POST ROUTES ---

// Create Post
app.post('/api/posts', verifyToken, async (req, res) => {
    try {
        const { caption, image } = req.body;
        const newPost = new Post({ caption, image, author: req.user.id });
        await newPost.save();
        res.status(201).json(newPost);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Feed Posts
app.get('/api/posts', verifyToken, async (req, res) => {
    try {
        const posts = await Post.find()
            .populate('author', 'username profilePic')
            .populate('comments.author', 'username')
            .sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Like / Unlike Post
app.put('/api/posts/:id/like', verifyToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Post not found' });

        if (post.likes.includes(req.user.id)) {
            post.likes.pull(req.user.id); // Unlike
        } else {
            post.likes.push(req.user.id); // Like
        }

        await post.save();
        res.json(post);
    } catch (err) {
        res.status(500).json({ error: