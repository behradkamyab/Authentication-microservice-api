const express = require("express");
const { body } = require("express-validator");

const authController = require("../controllers/auth-controller");
const { isAuth } = require("../middlewares/isAuth");

const router = express.Router();

router.get("/", isAuth, authController.test);

router.post(
  "/signup",
  [
    body("email").not().isEmpty().trim().isEmail(),
    body("name").not().isEmpty().trim(),
    body("password").not().isEmpty().trim(),
  ],
  authController.signup
);

router.post(
  "/confirm-email/:userId",
  [body("token").trim().not().isEmpty()],
  authController.confirmEmail
);

router.post(
  "/login",
  [
    body("email").not().isEmpty().trim().isEmail(),
    body("password").not().isEmpty().trim(),
  ],
  authController.login
);

router.post(
  "/create-reset-password-token",
  [body("email").trim().not().isEmpty()],
  authController.createResetPassToken
);

router.put(
  "/update-password/:userId/:token",
  [body("password").not().isEmpty().trim()],
  authController.updatePassword
);

//isAuth middleware
router.put("/otp-enable", isAuth, authController.enableOtp);
router.put("/otp-disable", isAuth, authController.disableOtp);
//

router.post(
  "/otp-verify/:userId",
  [body("token").not().isEmpty().trim()],
  authController.verifyOtp
);

module.exports = router;
