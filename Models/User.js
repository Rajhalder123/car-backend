const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    name: {
        type: String, // Use JavaScript String type
        required: true,
        unique: true,
    },
    email: {
        type: String, // Use JavaScript String type
        required: true,
        unique: true,
    },
    password: {
        type: String, // Use JavaScript String type
        required: true,
    },
});

const UserModel = mongoose.model("users", UserSchema);

module.exports = UserModel;
