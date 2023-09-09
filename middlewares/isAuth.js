const jwt = require("jsonwebtoken");

const error = require("../error");

const privateKey = "thishastobeinenvvariable";
exports.isAuth = async (req, res, next) => {
  try {
    const authHeader = req.get("Authorization");
    if (!authHeader) {
      const err = error.errorHandling("Authentication failed!", 401);
      throw err;
    }
    const token = authHeader.split(" ")[1];
    const decodedtoken = jwt.verify(token, privateKey);
    if (!decodedtoken) {
      const err = error.errorHandling("Authentication failed!", 401);
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
