const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const UserModel = require("../Models/User");

const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        const user = await UserModel.findOne({ email });
        if (user) {
            return res.status(409).json({ 
                message: 'User already exists, you can login', 
                success: false 
            });
        }

        // Create new user
        const userModel = new UserModel({ name, email, password });
        userModel.password = await bcrypt.hash(password, 10);
        await userModel.save();

        res.status(201).json({
            message: 'Signup successful',
            success: true
        });

    } catch (err) {
        console.error(err); // Log the error for debugging purposes
        res.status(500).json({
            message: 'Internal server error ',
            success: false
        });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if JWT_SECRET is defined
        if (!process.env.JWT_SECRET) {
            throw new Error("JWT_SECRET is not defined in environment variables");
        }

        // Find user by email
        const user = await UserModel.findOne({ email });
        const errorMsg = 'Wrong Password....!';

        // If user is not found
        if (!user) {
            return res.status(403).json({ message: errorMsg, success: false });
        }

        // Check if passwords match
        const isPassEqual = await bcrypt.compare(password, user.password);
        if (!isPassEqual) {
            return res.status(403).json({ message: errorMsg, success: false });
        }

        // Generate JWT token
        const jwtToken = jwt.sign(
            { email: user.email, _id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Respond with success
        return res.status(200).json({
            message: 'Login successful',
            success: true,
            jwtToken,
            email,
            name: user.name,
        });

        } catch (err) {
        // Log the error for debugging
        console.error("Error during login:", {
            email: req.body?.email,
            error: err.message,
        });

        // Respond with a server error
        return res.status(500).json({
            message: 'Internal server error',
            success: false,
        });
    }
};


module.exports = {
    signup,
    login
};
