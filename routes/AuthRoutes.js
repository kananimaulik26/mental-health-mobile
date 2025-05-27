const express = require("express");
const router = express.Router();
const AuthController = require("../controller/AuthController");

router.post('/signup',AuthController.SignUp);
router.post('/confirm',AuthController.ConfirmSignUp);
router.post('/signin',AuthController.SignIn);
router.post('/resend-code',AuthController.ResendVerificationCode);
router.post('/logout',AuthController.Logout);




module.exports = router;
