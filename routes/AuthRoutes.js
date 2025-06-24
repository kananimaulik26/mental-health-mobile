const express = require("express");
const router = express.Router();
const AuthController = require("../controller/AuthController");
const multer = require('multer');
const upload = multer();

router.post('/signup', AuthController.SignUp);
router.post('/confirm', AuthController.ConfirmSignUp);
router.post('/signin', AuthController.SignIn);
router.post('/resend-code', AuthController.ResendVerificationCode);
router.post('/logout', AuthController.Logout);
router.post('/update-user', upload.single('profile'), AuthController.UpdateUser);
router.get('/get-user', AuthController.GetUser);
router.post('/get-token', AuthController.RefreshToken);
router.get('/google/callback', AuthController.googleCallback);
router.put('/update-password', AuthController.UpdatePassword);
router.post('/login-activity', AuthController.LoginActivity);


module.exports = router;
