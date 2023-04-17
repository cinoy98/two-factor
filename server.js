
const express = require("express");
const session = require("express-session");
const hbs = require("hbs");
const auth = require("./libs/auth");
const app = express();
const db= require("./libs/db")
const cors = require('cors');
// Authentication statuses
const authStatuses = Object.freeze({
  NEED_SECOND_FACTOR: "needSecondFactor",
  COMPLETE: "complete"
});
const corsOptions ={
  origin:'*', 
  credentials:true,            
  //access-control-allow-credentials:true
  optionSuccessStatus:200,
}
app.use(cors(corsOptions)) 
app.set("view engine", "html");
app.engine("html", hbs.__express);
app.set("views", "./views");
app.use(express.json());
app.use(express.static(__dirname + "/public"));
app.use(express.static("dist"));

app.use(
  session({
    // Specify a real secret here
    secret: "secret",
    resave: true,
    saveUninitialized: false,
    proxy: true,
    // cookie: {
    //   httpOnly: true,
    //   secure: true,
    //   sameSite: "none"
    // }
  })
);

function isAuthenticationComplete(req) {
  return req.session.name === "main";
}

function isAwaitingSecondFactor(req) {
  return req.session.authStatus === authStatuses.NEED_SECOND_FACTOR;
}

app.use((req, res, next) => {

  process.env.HOSTNAME = req.headers.host;
  const protocol = /^localhost/.test(process.env.HOSTNAME) ? "http" : "https";
  process.env.ORIGIN = `${protocol}://${process.env.HOSTNAME}`;
  if (
    req.get("x-forwarded-proto") &&
    req.get("x-forwarded-proto").split(",")[0] !== "https"
  ) {
    return res.redirect(301, process.env.ORIGIN);
  }
  req.schema = "https";
  next();
});

app.get("/", async (req, res) => {
  if (isAuthenticationComplete(req)) {
    // If the user is authenticated, redirect to the account page
    res.redirect(307, "/account");
    return;
  }
  // If the user is not authenticated, start a new "auth" session
  try {
    // "auth" is an intermediate session dedicated to authentication/signing in
    req.session.name = "auth";
    // "auth" expires after 3 minutes, this means the user has 3 minutes to authenticate
    const sessionLength = 3 * 60 * 1000;
    req.session.cookie.expires = new Date(Date.now() + sessionLength);
    // Render the index page
    res.render("index.html");
  } catch (e) {
    res.render(e);
  }
});

app.get("/account", (req, res) => {
  if (!isAuthenticationComplete(req)) {
    // If the user is not completely authenticated, redirect to the index page with the signin/signup form
    res.redirect(307, "/");
    return;
  }
  res.render("account.html", { username: req.session.username });
});

app.get("/second-factor", (req, res) => {
  if (!isAwaitingSecondFactor(req)) {
    res.redirect(302, "/");
    return;
  }
  if (isAuthenticationComplete(req)) {
    res.redirect(302, "/account");
    return;
  }
  res.render("second-factor.html");
});

app.use("/auth", auth);

app.get('/showSessionValues', function (req, res, next) {
  // Get the values of the session variables
  let sessionDetails = req.session;
  console.log("current session data")
  console.table(sessionDetails)

  console.log("environment variables", process.env)
  res.json({
    "sessionDetails":sessionDetails,
    "environment varaible":process.env
    // "request data":req
  })
});


(async () => {
  try {

      // connection to mongo 
      const mongoConnection = await db.connectToMongo();
      console.log("MONGO Connection successfull in index.js");

  }
  catch (err) {
      console.log(` Error while booting application from server.js : ${JSON.stringify(err.message)}`);
  }
})();
const port = 8080;
const listener = app.listen(port || process.env.PORT, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
