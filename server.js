require("dotenv").config(); // Load environment variables
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors"); // Allow cross-origin requests
const bodyParser = require("body-parser");
const AuthRouter = require("./Routes/AuthRouter");
const SellCarRouter = require('./Routes/SellCarRoute');
const ProductRouter = require('./Routes/ProductRouter');
const app = express();
const PORT = process.env.PORT || 8080;
const mongo_url = process.env.MONGO_CONN;

// Check for MongoDB connection string
if (!mongo_url) {
    console.error("Error: MONGO_CONN environment variable is not defined!");
    process.exit(1); // Exit the application
}

// MongoDB Connection
mongoose
    .connect(mongo_url
    )
    .then(() => console.log("MongoDB connected..."))
    .catch((err) => {
        console.error("MongoDB connection error:", err);
        process.exit(1); // Exit the application
    });

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());

// Routes
app.get("/ping", (req, res) => {
    res.send("PO");
});
app.use("/auth", AuthRouter); 

// Authentication routes
app.use('/sell', SellCarRouter); 

app.use('/products', ProductRouter);//ProductRouter
// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});