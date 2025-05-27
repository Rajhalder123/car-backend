const { signup,login } = require('../Controllers/AuthController');
const { signupValidation,loginValidation } = require('../Middlewares/AuthValidation');

const router = require('express').Router();

// Define routes
router.post('/login', loginValidation, login);

// signup route
router.post('/signup', signupValidation, signup);

module.exports = router;
