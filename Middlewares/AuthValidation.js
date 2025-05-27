const Joi = require("joi");

// Signup validation middleware allowing extra fields
const signupValidation = (req, res, next) => {
  const schema = Joi.object({
    name: Joi.string().min(3).max(100).required(),
    email: Joi.string().email().max(100).required(),
    password: Joi.string().min(4).max(100).required(),
  }).unknown(true);  // allow additional unknown fields

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: "Validation failed",
      errors: error.details.map(detail => detail.message),
    });
  }
  next();
};

// Login validation middleware (same, but no extra fields needed typically)
const loginValidation = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().max(100).required(),
    password: Joi.string().min(4).max(100).required(),
  }).unknown(true); // allow extra fields here too if you want

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: "Validation failed",
      errors: error.details.map((detail) => detail.message),
    });
  }
  next();
};

module.exports = { signupValidation, loginValidation };
