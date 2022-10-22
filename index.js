require("dotenv").config();

const express = require("express");
const app = express();

//Import EJS and LAYOUT
const ejs = require("ejs");
const ejsLayout = require("express-ejs-layouts");

//Import Passport and Session
const passport = require("passport");
const session = require("express-session");

//Import Passport Configuration
require("./passport")(passport);

const PORT = process.env.APP_PORT || 4040;
const connectDB = require("./db/connect");
const flash = require("connect-flash");

//Import Authentication Middlware
const { ensureAuth } = require("./middleware/authentication");

//Import jsonwebtoken
const { sign } = require("jsonwebtoken");

//Save Session to database
const MongoStore = require("connect-mongo");
const cookieParser = require("cookie-parser");

//Initialize Middleware
app.use(ejsLayout);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

//Template engine
app.set("view engine", "ejs");
app.set("layout", "./layout/main");

//Cookie Parser
app.use(cookieParser(process.env.JWT_SECRET));

//Initialize session
app.use(
  session({
    name: "Passport Authentication",
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { maxAge: 60 * 60 * 1000, signed: true },
    store: MongoStore.create({
      mongoUrl: process.env.DB_URI,
      ttl: 1 * 24 * 60 * 60,
    }),
  })
);
//Initialize Passport
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use((req, res, next) => {
  res.locals.message = req.flash();
  next();
});

//Routes
app.get("/", (req, res) => {
  res.send("Hello World");
});
//Home Page
app.get("/home-page", (req, res) => {
  res.render("home");
});
//Signup Page
app.get("/signup-page", (req, res) => {
  res.render("signup");
});
//Login Page
app.get("/login-page", (req, res) => {
  res.render("login");
});

//JWT LOGIN
app.post("/login-jwt", async (req, res, next) => {
  passport.authenticate("login", async (err, user, info) => {
    try {
      if (err || !user) {
        return next(res.render("login"));
      }

      req.login(user, { session: false }, async (error) => {
        if (error) return next(error);

        const body = { id: user._id, username: user.username };
        const token = sign({ user: body }, process.env.JWT_SECRET);
        const oneHour = 60 * 60 * 1000;
        res.cookie("access-token", token, {
          httpOnly: true,
          signed: true,
          expires: new Date(Date.now() + oneHour),
          secure: process.env.NODE_ENV === "production",
        });
        res.redirect("/jwt-dashboard");
      });
    } catch (error) {
      return next(error);
    }
  })(req, res, next);
});
//JWT Dashboard
app.get(
  "/jwt-dashboard",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    console.log({ message: "Success" });
    res.render("dashboard", { name: req.user.username });
  }
);

//Dashboard Page
app.get("/dashboard", ensureAuth, (req, res) => {
  res.render("dashboard",{name: req.user.username});
});
//Logout
app.get("/logout", (req, res) => {
  res.cookie("access-token", "logout", {
    httpOnly: true,
    signed: true,
    expires: new Date(Date.now() + 1000),
  });
  req.logout((error) => {
    if (error) {
      return next(error);
    }
    res.redirect("/home-page");
  });
});

//Signup endpoint
app.post(
  "/signup",
  passport.authenticate("signup", { failureRedirect: "/signup-page" }),
  (req, res) => {
    res.redirect("/login-page");
  }
);
//Login endpoint
app.post(
  "/login",
  passport.authenticate("login", {
    failureRedirect: "/login-page",
    failureFlash: true,
  }),
  (req, res) => {
    req.flash("loginMessage");
    console.log(req.user);
    console.log(req.session);
    // console.log(req);
    res.redirect("/dashboard");
  }
);

//Google Oauth

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login-page",
  })
);

//Facebook Oauth
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login-page" }),
  function (req, res) {
    res.redirect("/dashboard");
  }
);
//Connect to database and start server
const start = async () => {
  await connectDB(process.env.DB_URI);
  app.listen(PORT, (err) => {
    if (err) throw err;
    console.log(
      `Server started in ${process.env.NODE_ENV} mode on port:${PORT}`
    );
  });
};
start();
