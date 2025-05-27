const express = require("express");
const router = express.Router();
const AuthRoutes = require("./AuthRoutes");

router.use("/auth", AuthRoutes);

module.exports = router;
