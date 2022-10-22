const User = require("./models/User");
const LocalStrategy = require("passport-local").Strategy;
const JWTStrategy = require("passport-jwt").Strategy;
const ExtractJWT = require("passport-jwt").ExtractJwt;
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
module.exports = function (passport) {
  passport.use(
    "signup",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: true,
      },
      async (req, email, password, done) => {
        process.nextTick(() => {
          User.findOne({ email }, (err, user) => {
            if (err) {
              return done(err, false);
            }
            if (user) {
              return done(
                null,
                false,
                req.flash("signupMessage", "User already exist")
              );
            } else {
              // if there is no user with that email
              // create the user
              var newUser = new User();

              // set the user's local credentials

              newUser.email = email;
              newUser.password = password;
              newUser.firstname = req.body.firstname;
              newUser.lastname = req.body.lastname;
              newUser.username = req.body.username;
              newUser.save((err) => {
                if (err) {
                  return done(err, false);
                }
                done(null, newUser);
              });
              // save the user
            }
          });
        });
      }
    )
  );
  passport.use(
    "login",
    new LocalStrategy(
      {
        usernameField: "username",
        passwordField: "password",
        passReqToCallback: true,
      },
      async (req, username, password, done) => {
        if (!username || !password) {
          done(
            null,
            false,
            req.flash(
              "loginMessage",
              "Username does not exist, Please enter an existing mail or register"
            )
          );
        }
        try {
          const user = await User.findOne({ username });
          if (!user) {
            done(
              null,
              false,
              req.flash("loginMessage", "Email does not exist")
            );
          }
          const checkPass = await user.comparePassword(password);
          if (!checkPass) {
            done(null, false, req.flash("loginMessage", "Password Incorrect"));
          }
          done(null, user);
        } catch (err) {
          done(
            err,
            false,
            req.flash("loginMessage", "Email or Password Incorrect")
          );
        }
      }
    )
  );
  //Cookie Extractor
  var cookieExtractor = function (req) {
    var token = null;
    if (req && req.signedCookies) {
      token = req.signedCookies["access-token"];
    }
    return token;
  };
  passport.use(
    "jwt",
    new JWTStrategy(
      {
        secretOrKey: process.env.JWT_SECRET,
        jwtFromRequest: cookieExtractor,
      },
      async function (jwt_payload, done) {
        // console.log(jwt_payload);
        const user = await User.findOne({ _id: jwt_payload.user.id });
        // console.log(user);
        done(null, user);
      }
    )
  );

  passport.use(
    "google",
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:4050/auth/google/callback",
        passReqToCallback: true,
      },
      async (request, accessToken, refreshToken, profile, done) => {
        console.log(profile);
        const newUser = {
          username: profile.displayName,
          firstname: profile.given_name,
          lastname: profile.family_name,
          oauthID: profile.id,
          password: 1234567890,
          email: profile.email,
        };
        try {
          let user = await User.findOne({ oauthID: profile.id });
          if (user) {
            done(null, user, { message: "User already exist" });
          } else {
            user = await User.create(newUser);
            done(null, user, { message: "User successfully created" });
          }
        } catch (err) {
          done(err);
        }
      }
    )
  );
  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:4050/auth/facebook/callback",
      },
      async function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        const newUser = {
          username: profile.displayName,
          firstname: profile.name.givenName,
          lastname: profile.familyName,
          oauthID: profile.id,
          password: 2345678901,
          email: profile.email,
        };
        try {
          let user = await User.findOne({ oauthID: profile.id });
          if (user) {
            cb(null, user, { message: "User already exist" });
          } else {
            user = await User.create(newUser);
            cb(null, user, { message: "User successfully created" });
          }
        } catch (err) {
          cb(err);
        }
      }
    )
  );
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
      done(err, user);
    });
  });
};
