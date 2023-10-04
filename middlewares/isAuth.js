const jwt = require("jsonwebtoken");
require("dotenv").config();

const privateKey = process.env.PRIVATE_KEY;
exports.isAuth = async (req, res, next) => {
  try {
    const authHeader = req.get("Authorization");
    if (!authHeader) {
      const err = new Error("Authentication failed!");
      err.statusCode = 401;
      throw err;
    }
    const token = authHeader.split(" ")[1];
    const decodedtoken = jwt.verify(token, privateKey);
    if (!decodedtoken) {
      const err = new Error("Authentication failed!");
      err.statusCode = 401;
      throw err;
    }
    req.userId = decodedtoken.userId;
    next();
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
