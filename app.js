const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
require("dotenv").config();

const authRoutes = require("./routes/auth-routes");

const PORT = process.env.PORT;
const DB_URL = process.env.DB_URL;

const app = express();
app.use(bodyParser.json());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "OPTIONS, GET, POST, PUT, PATCH, DELETE"
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

app.use("/api/", authRoutes);

app.use((error, req, res, next) => {
  const status = error.statusCode;
  const message = error.message;
  const data = error.data;

  res
    .status(status)
    .json({ success: false, message: message, status: status, data: data });
});

const DbConnection = mongoose.connect(DB_URL);
if (DbConnection) {
  app.listen(PORT);
}
