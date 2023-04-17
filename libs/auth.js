

const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const fido2 = require("@simplewebauthn/server");
const base64url = require("base64url");
const { check, validationResult } = require("express-validator");
const mongoDb = require("./db")

router.use(express.json());



// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

// WebAuthn settings
const authSettings = Object.freeze({
  RP_NAME: "main-project",
  FIDO_TIMEOUT: 30 * 1000 * 60,
  // Use "cross-platform" for roaming keys (= physical)
  AUTHENTICATOR_ATTACHEMENT: "cross-platform",
  RESIDENT_KEY: "preferred",
  REQUIRE_RESIDENT_KEY: false,
  USER_VERIFICATION: "preferred"
});

// Authentication types
const authTypes = Object.freeze({
  SINGLE_FACTOR: "sfa",
  TWO_FACTOR: "2fa"
});

// Authentication statuses
const authStatuses = Object.freeze({
  NEED_SECOND_FACTOR: "needSecondFactor",
  COMPLETE: "complete"
});

// Generic message, because an attacker should not be able to determine that a password was correct by looking at the error messages
const GENERIC_AUTH_ERROR_MESSAGE =
  "Username or password incorrect or credential not found or user verification failed";

// ----------------------------------------------------------------------------
// Utils
// ----------------------------------------------------------------------------

function isPasswordCorrect(username, password) {
  // Always true, in this demo for simplicity the password isn't actually checked
  return true;
}

function getAuthType(credentials) {
  // If one or more credential are registered, it means by definition that two-factor authentication is set up
  return credentials.length > 0
    ? authTypes.TWO_FACTOR
    : authTypes.SINGLE_FACTOR;
}

function csrfCheck(req, res, next) {
  if (req.header("X-Requested-With") != "XMLHttpRequest") {
    res.status(400).json({ error: "Invalid access" });
    return;
  }
  next();
}

function sessionCheck(req, res, next) {
  if (req.session.name !== "main") {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  next();
}

function getOrigin(userAgent) {
  let origin = "";
  if (userAgent.indexOf("okhttp") === 0) {
    const octArray = process.env.ANDROID_SHA256HASH.split(":").map(h =>
      parseInt(h, 16)
    );
    const androidHash = base64url.encode(octArray);
    origin = `android:apk-key-hash:${androidHash}`;
  } else {
    origin = process.env.ORIGIN;
  }
  return origin;
}

// ----------------------------------------------------------------------------
// Database management and actions
// ----------------------------------------------------------------------------


async function findUserByUsername(username) {

  const user = mongoDb.User.findOne({ username }).lean();
  return user;

}

async function createUser(user) {
  const newUser = await mongoDb.User.create(user);
  return newUser.toObject();
}

async function updateUser(username, user) {
  await mongoDb.User.findOneAndUpdate({ username }, user);
}

async function updateCredentials(username, credentials) {
  await mongoDb.User.findOneAndUpdate({ username }, { credentials });
}

async function createOrGetUser(username) {
  let user = await findUserByUsername(username);
  // If the user doesn't exist, create it
  if (!user) {

    user = {
      username,
      id: base64url.encode(crypto.randomBytes(32)),
      credentials: []
    };

    await createUser(user);
  }

  return user;
}

// ----------------------------------------------------------------------------
// Session management
// ----------------------------------------------------------------------------

// Sign out
router.get("/signout", (req, res) => {
  // Remove the session
  req.session.destroy();
  // Redirect to `/`
  res.redirect(307, "/");
});


function completeAuthentication(req, res) {
  // username and isPasswordCorrect come from the bootstrapping session, named 'auth', and dedicated to authentication
  const { username, isPasswordCorrect } = req.session;
  if (!username || !isPasswordCorrect) {
    res.status(401).json({ error: GENERIC_AUTH_ERROR_MESSAGE });
    return;
  }
  const risk = req.session.risk;
  // Terminate the 'auth' session and start the 'main' session
  // Once the 'main' session is active, the user is considered fully authenticated
  req.session.regenerate(function (err) {
    req.session.name = "main";
    // Transfer the username from the 'auth' session to the new one 'main'
    req.session.username = username;
    req.session.save(function (err) {
      res.status(200).json({
        msg: "Authentication complete",
        authStatus: authStatuses.COMPLETE,
        riskStatus: risk
      });
    });
  });
}


router.post(
  "/initialize-authentication",
  check("username")
    .notEmpty()
    .isAlphanumeric()
    .escape(),
  check("password")
    .notEmpty()
    .escape(),
  async (req, res) => {
    // Validate the input
    const validationErrors = validationResult(req);
    if (!validationErrors.isEmpty()) {
      res.status(400).json({
        error: "Username or password is empty or contains invalid characters"
      });
      return;
    }
    const { password, username, riskCategory } = req.body;
    const user = await createOrGetUser(username);

    const sampleUser = {
      Attacker: {
        "time": "2021-02-28 23:58:40.083",
        "UserID": "-4324475583306591935",
        "Rtt": 1748.0,
        "IPAddress": "103.148.128.209",
        "Country": "PK",
        "Region": "Punjab",
        "City": "Jaranwala",
        "asn": 29492,
        "UserAgentString": "Mozilla/5.0  (Linux; U; Android 2.2) Gecko/20150101 Firefox/20.0.0.1602 (Chrome",
        "Browser": "Firefox 20.0.0.1602",
        "os": "Android 2.2",
        "Device": "mobile",
        "LoginSuccessful": 0,
        "IsAttackIP": 1
      },
      Suspicious: {
        "time": "2020-02-03 12:44:30.475",
        "UserID": "5508122890022967325",
        "Rtt": 450.0,
        "IPAddress": "10.0.8.75",
        "Country": "NO",
        "Region": "Oslo County",
        "City": "Oslo",
        "asn": 29492,
        "UserAgentString": "Mozilla/5.0  (Linux; Android 5.5.1; CHM-U01) AppleWebKit/537.36 (KHTML, like Gecko Version/4.0 Chrome/30.0.0.2265.2272.0 Mobile Safari/537.36 SVN/060FSG2",
        "Browser": "Chrome Mobile WebView 30.0.0.2265.2272",
        "os": "Android 5.5.1",
        "Device": "mobile",
        "LoginSuccessful": false,
        "IsAttackIP": true,
        "IsAccountTakeover": false
      },
      Genuine: {
        "time": "2021-02-28 14:58:40.083",
        "UserID": "-5899288722986259008",
        "Rtt": 518,
        "IPAddress": "46.212.66.182",
        "Country": "NO",
        "Region": "Oslo County",
        "City": "Oslo",
        "asn": 41164,
        "UserAgentString": "Mozilla/5.0  (Linux; U; Android 5.4.3; en-us; GT-I9060 Build/JDQ39) AppleWebKit/533.1 (KHTML, like Gecko Version/4.0 Mobile Safari/533.1 variation/69385",
        "Browser": "Android 2.3.3.2660",
        "os": "Android 5.4.3",
        "Device": "mobile",
        "LoginSuccessful": 1,
        "IsAttackIP": 0
      }
    }
    // Set the username in the 'auth' session so that it can be passed to the main session
    req.session.username = username;
    let risk;
    let riskInput = sampleUser[riskCategory]
    const riskResponse = await mongoDb.fetchData(riskInput);
    console.log("riskResponse in auth.js", JSON.stringify(riskResponse))
    const anomaly = riskResponse.anomaly[0];
    const score = riskResponse.score[0];
    if (anomaly == -1) {
      risk = "HIGH"
    }
    else {
      if (score > 0.14) {
        risk = "LOW"
      }
      else {
        risk = "MEDIUM"
      }
    }
    req.session.risk = risk
    console.log("risk in session", risk)
    // Set the password correctness value for the next step
    req.session.isPasswordCorrect = isPasswordCorrect(username, password);
    // If 2FA is not set up, complete the authentication
    const authType = getAuthType(user.credentials);
    if (authType === authTypes.SINGLE_FACTOR) {
      completeAuthentication(req, res);
      // If 2FA is set up, respond with a signal that the second factor is missing
    } else if (authType === authTypes.TWO_FACTOR) {
      if (risk == "MEDIUM") {
        // Set the authStatus in the session so that it can be checked in server.js
        req.session.authStatus = authStatuses.NEED_SECOND_FACTOR;
        // And set it in the response so that it can be checked by the client
        res.status(200).json({
          msg:
            "Need two factors because two-factor-authentication was configured for this account",
          authStatus: authStatuses.NEED_SECOND_FACTOR,
          riskStatus: risk
        });
      }
      else if (risk == "LOW") {
        completeAuthentication(req, res);
      }
      else if (risk == "HIGH") {
       
        // And set it in the response so that it can be checked by the client
        res.status(200).json({
          msg:
            "HIGH RISK DETECTED",
          authStatus: authStatuses.NEED_SECOND_FACTOR,
          riskStatus: risk
        });
      }
    } else {
      res.status(500).json({ error: "Unkown authentication type" });
    }
  }
);


router.post("/two-factor-options", csrfCheck, async (req, res) => {
  try {
    const user = await findUserByUsername(req.session.username);
    const userVerification = "preferred";
    const allowCredentials = [];
    for (let cred of user.credentials) {
      allowCredentials.push({
        id: cred.credId,
        type: "public-key",
        transports: cred.transports || []
      });
    }
    const options = fido2.generateAssertionOptions({
      timeout: authSettings.FIDO_TIMEOUT,
      rpID: process.env.HOSTNAME,
      allowCredentials,
      // userVerification is an optional value that controls whether or not the authenticator needs be able to uniquely
      // identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
      userVerification
    });
    req.session.challenge = options.challenge;

    res.status(200).json(options);
  } catch (e) {
    res.status(400).json({
      error: `Getting two-factor authentication options failed: ${GENERIC_AUTH_ERROR_MESSAGE}`
    });
  }
});


router.post("/authenticate-two-factor", csrfCheck, async (req, res) => {
  const { body } = req;
  const { credential: credentialFromClient } = body;
  const expectedOrigin = getOrigin(req.get("User-Agent"));
  const expectedRPID = process.env.HOSTNAME;
  const {
    username,
    isPasswordCorrect,
    challenge: expectedChallenge
  } = req.session;
  if (!username || !isPasswordCorrect) {
    res.status(401).json({
      error: `Authentication failed: ${GENERIC_AUTH_ERROR_MESSAGE}`
    });
  }
  const user = await findUserByUsername(username);
  let credentialFromServer = user.credentials.find(
    cred => cred.credId === credentialFromClient.id
  );
  if (!credentialFromServer) {
    res.status(401).json({
      error: `Authentication failed: ${GENERIC_AUTH_ERROR_MESSAGE}`
    });
  }
  try {
    const verification = fido2.verifyAssertionResponse({
      credential: credentialFromClient,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator: credentialFromServer
    });
    const { verified, authenticatorInfo } = verification;
    if (!verified) {
      res.status(401).json({
        error: `Authentication failed: ${GENERIC_AUTH_ERROR_MESSAGE}`
      });
    }
    updateUser(username, user);
    delete req.session.challenge;
    completeAuthentication(req, res);
  } catch (e) {
    delete req.session.challenge;
    res.status(400).json({ error: e.message });
  }
});

// ----------------------------------------------------------------------------
// Credential management
// ----------------------------------------------------------------------------


router.get("/credentials", csrfCheck, sessionCheck, async (req, res) => {
  const { username } = req.session;
  const user = await findUserByUsername(username);
  res.status(200).json(user || {});
});


router.delete("/credential", csrfCheck, sessionCheck, async (req, res) => {
  const { credId } = req.query;
  const { username } = req.session;
  const user = await findUserByUsername(username);
  const updatedCredentials = user.credentials.filter(cred => {
    return cred.credId !== credId;
  });
  updateCredentials(username, updatedCredentials);
  res.status(200).json(user || {});
});


router.put(
  "/credential",
  csrfCheck,
  sessionCheck,
  check("credId").escape(),
  check("name")
    .trim()
    .escape(),
  async (req, res) => {
    // Validate the input
    const validationErrors = validationResult(req);
    if (!validationErrors.isEmpty()) {
      return res.status(400).json({ error: validationErrors.array() });
    }

    const { credId, name: newName } = req.query;

    try {
      const { username } = req.session;
      const user = await findUserByUsername(username);
      const { credentials } = user;
      const indexOfCredentialToUpdate = credentials.findIndex(
        el => el.credId === credId
      );
      // Change the credential name on a copy of the credentials
      const updatedCredentials = [...credentials];
      // Normally empty name in the frontend means the renaming request is not sent. This is an extra protection
      updatedCredentials[indexOfCredentialToUpdate].name = newName || "";
      // Update the stored credentials with the copy
      updateCredentials(username, updatedCredentials);
      res.status(200).json(user);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  }
);


router.post(
  "/credential",
  csrfCheck,
  sessionCheck,
  check("credId").escape(),
  async (req, res) => {
    const { challenge: expectedChallenge, username } = req.session;
    const { body } = req;
    const { id: credId, transports, credProps } = body;
    const expectedOrigin = getOrigin(req.get("User-Agent"));
    const expectedRPID = process.env.HOSTNAME;

    try {
      // Verify the user via fido
      const verification = await fido2.verifyAttestationResponse({
        credential: body,
        expectedChallenge,
        expectedOrigin,
        expectedRPID
      });
      const { verified, authenticatorInfo } = verification;
      if (!verified) {
        return res.status(400).json({ error: "User verification failed" });
      }
      // Validate the input
      const validationErrors = validationResult(req);
      if (!validationErrors.isEmpty()) {
        return res.status(400).json({ error: validationErrors.array() });
      }
      const { base64PublicKey, base64CredentialID } = authenticatorInfo;
      const user = await findUserByUsername(username);
      const existingCred = user.credentials.find(
        cred => cred.credID === base64CredentialID
      );
      if (!existingCred) {
        const newCredential = {
          publicKey: base64PublicKey,
          credId: base64CredentialID,
          // the credential isn't given a name upon creation
          name: "",
          transports: transports || [],
          creationDate: Date.now()
        };
        // Add the "is resident key" info if available i.e. if the client has supplied credProps
        if (credProps) {
          newCredential.isResidentKey = credProps.rk;
        }
        // Add the returned device to the user's list of devices
        user.credentials.push(newCredential);
      }
      updateUser(username, user);
      delete req.session.challenge;
      // Respond with user data
      res.json(user);
    } catch (e) {
      delete req.session.challenge;
      res.status(400).json({ error: e.message });
    }
  }
);


router.post(
  "/credential-options",
  csrfCheck,
  sessionCheck,
  async (req, res) => {
    const { username } = req.session;
    const user = await findUserByUsername(username);
    try {
      // excludeCredentials represent the existing authenticators
      const excludeCredentials = [];
      if (user.credentials.length > 0) {
        for (let cred of user.credentials) {
          excludeCredentials.push({
            id: cred.credId,
            type: "public-key",
            transports: cred.transports || []
          });
        }
      }

      const options = fido2.generateAttestationOptions({
        rpName: authSettings.RP_NAME,
        rpID: process.env.HOSTNAME,
        userID: user.id,
        userName: username,
        timeout: authSettings.FIDO_TIMEOUT,
        // Prompt user for additional information about the authenticator
        // Prevent user from re-registering existing authenticators
        excludeCredentials,
        authenticatorSelection: {
          authenticatorAttachment: authSettings.AUTHENTICATOR_ATTACHEMENT,
          residentKey: authSettings.RESIDENT_KEY,
          requireResidentKey: authSettings.REQUIRE_RESIDENT_KEY,
          userVerification: authSettings.USER_VERIFICATION
        },

        pubKeyCredParams: [
          {
            type: "public-key",
            alg: -7
          },
          {
            type: "public-key",
            alg: -257
          }
        ]
      });
      req.session.challenge = options.challenge;
      res.status(200).json(options);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  }
);

module.exports = router;
