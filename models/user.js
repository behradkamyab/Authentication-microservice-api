const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const userSchema = new Schema(
  {
    phoneNumber: {
      type: Number,
      required: true,
      unique: true,
    },
    name: {
      type: String,
      lowercase: true,
      required: true,
    },
    password: {
      type: String,
      required: true,
      disbale: false,
    },
    resetToken: { type: String },
    resetTokenExpiration: { type: Date },
    confirmation: {
      isEnable: { type: Boolean, default: false },
      confirmationCode: { type: String },
      confirmationTokenExpiration: { type: Date },
    },
    otp: {
      isEnable: { type: Boolean, default: false },
      otpSecret: {
        type: String,
      },
      otpExpiration: {
        type: Date,
      },
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
