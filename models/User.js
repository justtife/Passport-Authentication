const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const validator = require("validator");

const userSchema = new mongoose.Schema({
  firstname: {
    type: String,
    // required: true,  
    minlength: [3, "Please enter more than 2 chraracters"],
  },
  lastname: {
    type: String,
    // required: true,
    minlength: [3, "Please enter more than 2 chraracters"],
  },
  email: {
    type: String,
    validate: {
      validator: validator.isEmail,
      message: "Please enter a valid Email",
    },
    unique: [true, "Email Already exist"],
    // required: true,
  },
  username: {
    type: String,
  },
  oauthID: {
    type: Number,
  },
  password: {
    type: String,
    required: true,
    minlength: [6, "Password should contain more than 5 Characters"],
  },
});

userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (userPassword) {
  const isValid = await bcrypt.compare(userPassword, this.password);
  return isValid;
};

module.exports = mongoose.model("User", userSchema);
