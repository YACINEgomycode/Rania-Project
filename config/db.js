const mongoose = require("mongoose");
const config = require("config");
const mongodb = async () => {
  try {
    await mongoose.connect(config.get("mongoURI"), {
      useUnifiedTopology: true,
      useNewUrlParser: true
    });
    console.log("MongoDB Connected");
  } catch (err) {
    console.log(err);
    process.exit(1);
  }
};

module.exports = mongodb;