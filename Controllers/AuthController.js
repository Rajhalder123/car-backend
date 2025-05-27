const bcrypt = require('bcrypt.js');
const jwt = require('jsonwebtoken');
const UserModel = require("../Models/User");

// SIGNUP CONTROLLER
const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validate input
        if (!name || !email || !password) {
            return res.status(400).json({
                message: 'All fields are required',
                success: false
            });
        }

        // Check if user already exists
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(409).json({
                message: 'User already exists, you can login',
                success: false
            });
        }

        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new UserModel({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({
            message: 'Signup successful',
            success: true
        });

    } catch (err) {
        console.error("Error during signup:", err.message);
        res.status(500).json({
            message: 'Internal server error',
            success: false
        });
    }
};

// LOGIN CONTROLLER
const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                message: 'Email and password are required',
                success: false
            });
        }

        // Check if JWT_SECRET is defined
        if (!process.env.JWT_SECRET) {
            throw new Error("JWT_SECRET is not defined in environment variables");
        }

        // Find user by email
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(403).json({
                message: 'Invalid credentials',
                success: false
            });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(403).json({
                message: 'Invalid credentials',
                success: false
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { email: user.email, _id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Send response
        res.status(200).json({
            message: 'Login successful',
            success: true,
            token,
            email,
            name: user.name,
        });

    } catch (err) {
        console.error("Error during login:", {
            email: req.body?.email,
            error: err.message,
        });

        res.status(500).json({
            message: 'Internal server error',
            success: false
        });
    }
};

module.exports = {
    signup,
    login
};
