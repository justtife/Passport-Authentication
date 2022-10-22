const mongoose = require("mongoose");

const connectDB = async (url) => {
  try {
    await mongoose.connect(url);
    console.log("Database Connected");
  } catch (err) {
    console.error(`Database Error; ${err}`);
  }
};

module.exports = connectDB;
