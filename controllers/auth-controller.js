const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
require("dotenv").config();

const helper = require("../utilities/helper");

// const phoneNumberRegex = /09[0-3][0-9]-?[0-9]{3}-?[0-9]{4}/;
const passRegex = /^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\W)(?!.* ).{8,16}$/;
const privateKey = process.env.PRIVATE_KEY;

const User = require("../models/user");

const { validationResult } = require("express-validator");

exports.signup = async (req, res, next) => {
  const phoneNumber = req.body.phoneNumber;
  const password = req.body.password;
  const confirmPass = req.body.confirmPassword;
  const name = req.body.name;
  let imageUrl;
  const errors = validationResult(req);
  let user;
  try {
    if (!errors.isEmpty()) {
      const err = new Error("Validation failed!");
      err.statusCode = 422;
      err.data = errors.array();
      throw err;
    }
    // if (!phoneNumber.match(phoneNumberRegex)) {
    //   const err = new Error("Enter the right phone number");
    //   err.statusCode = 422;
    //   throw err;
    // }
    if (!password.match(passRegex)) {
      const err = new Error(
        "Password must contain one digit from 1 to 9, one lowercase letter, one uppercase letter, one special character, no space, and it must be 8-16 characters long."
      );
      err.statusCode = 422;
      throw err;
    }
    if (req.file) {
      imageUrl = req.file.path.replace("\\", "/");
    }
    user = await User.findOne({ phoneNumber: phoneNumber });
    if (user) {
      const err = new Error("This phone number has already signed up!");
      err.statusCode = 422;
      throw err;
    }
    if (password !== confirmPass) {
      const err = new Error("Passwords do not match!");
      err.statusCode = 422;
      throw err;
    }
    const hashedPass = await bcrypt.hash(password, 10);
    user = new User({
      phoneNumber: phoneNumber,
      name: name,
      password: hashedPass,
      profilePic: imageUrl,
    });

    const token = crypto.randomInt(1000, 9999).toString();
    const hashedToken = await bcrypt.hash(token, 10);
    console.log(hashedToken);
    if (!hashedToken) {
      const err = new Error("something went wrong");
      err.statusCode = 500;
      throw err;
    }
    user.confirmation.confirmationCode = hashedToken;
    user.confirmation.confirmationTokenExpiration = Date.now() + 3600000;
    const result = await user.save();
    if (result) {
      //send confirmation with sms to user
      res.status(201).json({
        success: true,
        userId: result._id.toString(),
        confirmationCode: token,
      });
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.confirmPhoneNumber = async (req, res, next) => {
  const userId = req.params.userId;
  const token = req.body.token;
  const errors = validationResult(req);
  try {
    if (!errors.isEmpty()) {
      const err = new Error("Validation failed!");
      err.statusCode = 422;
      err.data = errors.array();
      throw err;
    }
    const user = await User.findOne({ _id: userId });
    if (!user) {
      const err = new Error("there is no user with this phone number!");
      err.statusCode = 404;
      throw err;
    }

    const doMatch = await bcrypt.compare(
      token,
      user.confirmation.confirmationCode
    );

    if (!doMatch) {
      const err = new Error("Confirmation code is wrong");
      err.statusCode = 422;
      throw err;
    }
    if (user.confirmation.confirmationTokenExpiration.getTime() <= Date.now()) {
      const err = new Error("Confirmation code has expired");
      err.statusCode = 422;
      throw err;
    }
    user.confirmation.isEnable = true;
    user.confirmation.confirmationTokenExpiration = undefined;
    const result = await user.save();
    if (result) {
      res.status(200).json({
        success: true,
        message: "Your phone number has been confirmed!",
      });
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.login = async (req, res, next) => {
  const phoneNumber = req.body.phoneNumber;
  const password = req.body.password;
  const errors = validationResult(req);
  try {
    if (!errors.isEmpty()) {
      const err = new Error("Validation failed!");
      err.statusCode = 422;
      err.data = errors.array();
      throw err;
    }
    // if (!phoneNumber.match(phoneNumberRegex)) {
    //   const err = new Error("Enter the right phone number");
    //   err.statusCode = 422;
    //   throw err;
    // }

    const user = await User.findOne({ phoneNumber: phoneNumber });
    if (!user) {
      const err = new Error("There is no user with this phone number");
      err.statusCode = 404;
      throw err;
    }

    if (!user.confirmation.isEnable) {
      const err = new Error("Confirm your phone number first!");
      err.statusCode = 422;
      throw err;
    }
    const doMatch = await bcrypt.compare(password, user.password);
    if (!doMatch) {
      const err = new Error("Password do not match!");
      err.statusCode = 422;
      throw err;
    }
    if (user.otp.isEnable === true) {
      const token = crypto.randomInt(1000, 9999).toString();
      const hashedToken = await bcrypt.hash(token, 10);
      if (!hashedToken) {
        const err = new Error("something went wrong");
        throw err;
      }
      user.otp.otpSecret = hashedToken;
      user.otp.otpExpiration = Date.now() + 1000000;
      const result = await user.save();
      if (!result) {
        const err = new Error("something went wrong", 500);
        throw err;
      }
      //send token to user with sms
      res.status(200).json({
        success: true,
        message: "otp code has sent to the phone",
        otpCode: token,
        userId: user._id.toString(),
      });
    } else {
      const token = jwt.sign(
        {
          phoneNumber: user.phoneNumber,
          userId: user._id.toString(),
        },
        privateKey,
        { expiresIn: "1h" }
      );

      res
        .status(200)
        .json({ success: true, token: token, userId: user._id.toString() });
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.createResetPassToken = async (req, res, next) => {
  const phoneNumber = req.body.phoneNumber;
  const errors = validationResult(req);
  try {
    if (!errors.isEmpty()) {
      const err = new Error("Validation failed!");
      err.statusCode = 422;
      err.data = errors.array();
      throw err;
    }
    const user = await User.findOne({ phoneNumber: phoneNumber });
    if (!user) {
      const err = new Error("This phone number hasnt signedup yet!");
      err.statusCode = 422;
      throw err;
    }
    const token = crypto.randomInt(1000, 9999).toString();
    const hashedToken = await bcrypt.hash(token, 10);
    if (!hashedToken) {
      const err = new Error("something went wrong");
      throw err;
    }
    user.resetToken = hashedToken;
    user.resetTokenExpiration = Date.now() + 3600000;
    const result = await user.save();
    if (result) {
      //send email with token and userId
      res.status(200).json({
        success: true,
        token: token,
        userId: result._id.toString(),
      });
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.updatePassword = async (req, res, next) => {
  const userId = req.params.userId;
  const token = req.params.token;
  const password = req.body.password;
  const errors = validationResult(req);
  try {
    if (!errors.isEmpty()) {
      const err = new Error("Validation failed!");
      err.statusCode = 422;
      err.data = errors.array();
      throw err;
    }
    const user = await User.findOne({ _id: userId });
    if (!user) {
      const err = new Error("Cannot find the user!");
      err.statusCode = 404;
      throw err;
    }

    const tokenMatch = await bcrypt.compare(token, user.resetToken);

    if (!tokenMatch) {
      const err = new Error("Reset token is wrong");
      err.statusCode = 422;
      throw err;
    }
    if (user.resetTokenExpiration <= Date.now()) {
      const err = new Error("Your time has been expired!");
      err.statusCode = 422;
      throw err;
    }
    const doMatch = await bcrypt.compare(password, user.password);
    if (doMatch) {
      const err = new Error("new password cannot be like the old one");
      err.statusCode = 422;
      throw err;
    }
    if (!password.match(passRegex)) {
      const err = new Error(
        "Password must contain one digit from 1 to 9, one lowercase letter, one uppercase letter, one special character, no space, and it must be 8-16 characters long."
      );
      err.statusCode = 422;
      throw err;
    }
    const newPass = await bcrypt.hash(password, 10);
    user.password = newPass;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    const result = await user.save();
    if (result) {
      res.status(200).json({ success: true, userId: result._id });
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.enableOtp = async (req, res, next) => {
  const userId = req.userId;
  try {
    const user = await User.findById(userId);
    if (!user) {
      const err = new Error("This phone number hasnt signedup yet!");
      err.statusCode = 404;
      throw err;
    }
    user.otp.isEnable = true;
    const result = await user.save();
    if (result) {
      res
        .status(200)
        .json({ success: true, message: "OTP enabled successfully!" });
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.disableOtp = async (req, res, next) => {
  const userId = req.userId;
  try {
    const user = await User.findById(userId);
    if (!user) {
      const err = new Error("This phone number hasnt signedup yet!");
      err.statusCode = 404;
      throw err;
    }
    user.otp.isEnable = false;

    const result = await user.save();
    if (result) {
      res
        .status(200)
        .json({ success: true, message: "OTP disabled successfully!" });
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.verifyOtp = async (req, res, next) => {
  const token = req.body.token;
  const userId = req.params.userId;
  const errors = validationResult(req);
  try {
    if (!errors.isEmpty()) {
      const err = new Error("Validation failed!");
      err.statusCode = 422;
      err.data = errors.array();
      throw err;
    }
    const user = await User.findOne({ _id: userId });
    if (!user) {
      const err = new Error("This phone number hasnt signedup yet!");
      err.statusCode = 404;
      throw err;
    }
    const doMatch = await bcrypt.compare(
      token,
      user.confirmation.confirmationCode
    );

    if (!doMatch) {
      const err = new Error("OTP code is wrong");
      err.statusCode = 422;
      throw err;
    }
    if (user.otp.otpExpiration.getTime() <= Date.now()) {
      const err = new Error("Otp code has expired");
      err.statusCode = 422;
      throw err;
    }
    user.otp.otpSecret = undefined;
    user.otp.otpExpiration = undefined;
    const result = await user.save();
    if (result) {
      const loginToken = jwt.sign(
        {
          phoneNumber: user.phoneNumber,
          userId: user._id.toString(),
        },
        privateKey,
        { expiresIn: "1h" }
      );

      res.status(200).json({
        success: true,
        token: loginToken,
        userId: user._id.toString(),
      });
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
