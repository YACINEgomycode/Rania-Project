const express = require("express");
const passport = require("passport");
const app = express();
const cors = require("cors");


// Body & Header Parser
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors());


//passport Midleware
app.use(passport.initialize());

//passport Config
require("./Middleware/passport")(passport);

// Connexion BD
require("./config/db")();

// API Route
app.use(require("./routes/users"));

const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`Server running on port ${port}`));