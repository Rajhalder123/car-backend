const express = require("express");
const router = express.Router();
const SellCar = require("../Models/sell");


// POST route to handle sell car form submission
router.post("/", async (req, res) => {
  try {
    const newCar = new SellCar(req.body);
    await newCar.save();
    res.status(201).json({ message: "Car listing submitted successfully" });
  } catch (error) {
    console.error("Error saving car listing:", error);
    res.status(500).json({ error: "Failed to submit car listing" });
  }
});

module.exports = router;
