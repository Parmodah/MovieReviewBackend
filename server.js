const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();

process.on("uncaughtException", (err) => {
  console.log("UNCAUGHT EXCEPTION! 💥 shutting down...");
  console.log(err.name, err.message);
});

const app = require("./app");

mongoose
  .connect(process.env.DATABASE)
  .then(() => console.log("DB connection successful"));

const port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`App running on port ${port}...`);
});
