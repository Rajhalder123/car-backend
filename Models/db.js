const mongoose = require("mongoose"); // Fix typo: "mogoose" -> "mongoose"
const mongo_url = process.env.MONGO_CONN; // Fix typo: "process.envMONGO_CONN" -> "process.env.MONGO_CONN"

mongoose
    .connect(mongo_url, { useNewUrlParser: true, useUnifiedTopology: true }) // Add options for compatibility
    .then(() => {
        console.log("MongoDB connected..");
    })
    .catch((err) => {
        console.log("MongoDB connection error:", err);
    });
