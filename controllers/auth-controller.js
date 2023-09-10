const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const salt = 10;
const phoneNumberRegex = /09(0[1-2]|1[0-9]|3[0-9]|2[0-1])-?[0-9]{3}-?[0-9]{4}/;
const passRegex = /^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\W)(?!.* ).{8,16}$/;
const privateKey = "thishastobeinenvvariable";

const User = require("../models/user");
const error = require("../error");
const { validationResult } = require("express-validator");

exports.test = (req, res, next) => {
  res.send("hello");
};

exports.signup = async (req, res, next) => {
  const phoneNumber = req.body.phoneNumber;
  const password = req.body.password;
  const confirmPass = req.body.confirmPassword;
  const name = req.body.name;
  const errors = validationResult(req);
  let user;
  try {
    if (!errors.isEmpty()) {
      const err = error.errorHandling("Validation failed!", 422);
      err.data = errors.array();
      throw err;
    }
    if (!phoneNumber.match(phoneNumberRegex)) {
      const err = error.errorHandling("Enter the right phone number", 422);
      throw err;
    }
    if (!password.match(passRegex)) {
      const err = error.errorHandling(
        "Password must contain one digit from 1 to 9, one lowercase letter, one uppercase letter, one special character, no space, and it must be 8-16 characters long.",
        422
      );
      throw err;
    }
    user = await User.findOne({ phoneNumber: phoneNumber });
    if (user) {
      const err = error.errorHandling(
        "This phone number has already signed up!",
        422
      );
      throw err;
    }
    if (password !== confirmPass) {
      const err = error.errorHandling("Passwords do not match!", 422);
      throw err;
    }
    const hashedPass = await bcrypt.hash(password, salt);
    user = new User({
      phoneNumber: phoneNumber,
      name: name,
      password: hashedPass,
    });
    const token = crypto.randomInt(0, 9999).toString();
    const hashToken = await bcrypt.hash(token, salt);
    if (!hashToken) {
      const err = error.errorHandling("something went wrong", 500);
      throw err;
    }
    user.confirmation.confirmationCode = hashToken;
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
      const err = error.errorHandling("Validation failed!", 422);
      err.data = errors.array();
      throw err;
    }
    const user = await User.findOne({ _id: userId });
    if (!user) {
      const err = error.errorHandling(
        "there is no user with this phone number!",
        422
      );
      throw err;
    }
    const doMatch = await bcrypt.compare(
      token,
      user.confirmation.confirmationCode
    );
    if (!doMatch) {
      const err = error.errorHandling("Confirmation code is not valid", 422);
      throw err;
    }
    if (user.confirmation.confirmationTokenExpiration.getTime() <= Date.now()) {
      const err = error.errorHandling("Confirmation code has expired", 422);
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
      const err = error.errorHandling("Validation failed!", 422);
      err.data = errors.array();
      throw err;
    }
    if (!phoneNumber.match(phoneNumberRegex)) {
      const err = error.errorHandling("Enter the right phone number", 422);
      throw err;
    }

    const user = await User.findOne({ phoneNumber: phoneNumber });
    if (!user) {
      const err = error.errorHandling(
        "There is no user with this phone number",
        404
      );
      throw err;
    }

    if (!user.confirmation.isEnable) {
      const err = error.errorHandling("Confirm your phone number first!", 422);
      throw err;
    }
    const doMatch = await bcrypt.compare(password, user.password);
    if (!doMatch) {
      const err = error.errorHandling("Password do not match!", 422);
      throw err;
    }
    if (user.otp.isEnable === true) {
      const token = crypto.randomInt(0, 99999).toString();
      const hashToken = await bcrypt.hash(token, salt);
      if (!hashToken) {
        const err = error.errorHandling("something went wrong", 500);
        throw err;
      }
      user.otp.otpSecret = hashToken;
      user.otp.otpExpiration = Date.now() + 1000000;
      const result = await user.save();
      if (!result) {
        const err = error.errorHandling("something went wrong", 500);
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
      const err = error.errorHandling("Validation failed!", 422);
      err.data = errors.array();
      throw err;
    }
    const user = await User.findOne({ phoneNumber: phoneNumber });
    if (!user) {
      const err = error.errorHandling(
        "This phone number hasnt signedup yet!",
        404
      );
      throw err;
    }
    const buffer = crypto.randomBytes(32);
    const token = buffer.toString("hex");
    hashToken = await bcrypt.hash(token, salt);
    user.resetToken = hashToken;
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
      const err = error.errorHandling("Validation failed!", 422);
      err.data = errors.array();
      throw err;
    }
    const user = await User.findOne({ _id: userId });
    if (!user) {
      const err = error.errorHandling("Cannot find the user!", 404);
      throw err;
    }
    const tokenMatch = await bcrypt.compare(token, user.resetToken);
    if (!tokenMatch) {
      const err = error.errorHandling("Your reset token has been expired!");
      throw err;
    }
    if (user.resetTokenExpiration <= Date.now()) {
      const err = error.errorHandling("Your time has been expired!", 422);
      throw err;
    }
    const doMatch = await bcrypt.compare(password, user.password);
    if (doMatch) {
      const err = error.errorHandling(
        "new password cannot be like the old one",
        422
      );
      throw err;
    }
    if (!password.match(passRegex)) {
      const err = error.errorHandling(
        "Password must contain one digit from 1 to 9, one lowercase letter, one uppercase letter, one special character, no space, and it must be 8-16 characters long.",
        422
      );
      throw err;
    }
    const newPass = await bcrypt.hash(password, salt);
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
      const err = error.errorHandling(
        "This phone number hasnt signedup yet!",
        404
      );
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
      const err = error.errorHandling(
        "This phone number hasnt signedup yet!",
        404
      );
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
      const err = error.errorHandling("Validation failed!", 422);
      err.data = errors.array();
      throw err;
    }
    const user = await User.findOne({ _id: userId });
    if (!user) {
      const err = error.errorHandling(
        "This phone number hasnt signedup yet!",
        404
      );
      throw err;
    }
    const doMatch = await bcrypt.compare(token, user.otp.otpSecret);
    if (!doMatch) {
      const err = error.errorHandling("Otp code is wrong", 422);
      throw err;
    }
    if (user.otp.otpExpiration.getTime() <= Date.now()) {
      const err = error.errorHandling("Otp code has expired", 422);
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
