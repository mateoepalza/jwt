const crypto = require('crypto');
const jsonwebtoken = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// load private key
const pathToKeyPriv = path.join(__dirname, '..', 'id_rsa_priv.pem');
const PRIV_KEY = fs.readFileSync(pathToKeyPriv, 'utf-8');
// load public key
const pathToKeyPub = path.join(__dirname, '..', 'id_rsa_pub.pem');
const PUB_KEY = fs.readFileSync(pathToKeyPub, 'utf-8');

/**
 * -------------- HELPER FUNCTIONS ----------------
 */

/**
 * 
 * @param {*} password - The plain text password
 * @param {*} hash - The hash stored in the database
 * @param {*} salt - The salt stored in the database
 * 
 * This function uses the crypto library to decrypt the hash using the salt and then compares
 * the decrypted hash/salt with the password that the user provided at login
 */
function validPassword(password, hash, salt) {
  var hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash === hashVerify;
}

/**
 * 
 * @param {*} password - The password string that the user inputs to the password field in the register form
 * 
 * This function takes a plain text password and creates a salt and hash out of it.  Instead of storing the plaintext
 * password in the database, the salt and hash are stored for security
 * 
 * ALTERNATIVE: It would also be acceptable to just use a hashing algorithm to make a hash of the plain text password.
 * You would then store the hashed password in the database and then re-hash it to verify later (similar to what we do here)
 */
function genPassword(password) {
  var salt = crypto.randomBytes(32).toString('hex');
  var genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

  return {
    salt: salt,
    hash: genHash
  };
}


/**
 * @param {*} user - The user object.  We need this to set the JWT `sub` payload property to the MongoDB user ID
 */
function issueJWT(user) {
  const _id = user._id;

  //the JWT expires in 1d
  const expiresIn = '1d';

  // this is the payload od the jwt
  const payload = {
    // the user id
    sub: _id,
    // issue at, the current time
    iat: Date.now()
  };

  // we signed the token, be aware that we are passing the expiration time and the algorith that we used
  const signedToken = jsonwebtoken.sign(payload, PRIV_KEY, { expiresIn: expiresIn, algorithm: 'RS256' });

  // Be aware that this Bearer is needed because in the extraction of the jwt we stablished the method
  // fromAuthHeaderAsBearerToken() which expects something like that:
  return {
    token: "bearer " + signedToken,
    expires: expiresIn
  }
}

function authMiddleware(req, res, next) {
  // We take the authorization element and we split the string to get bearer and the token
  const tokenParse = req.headers.authorization.split(' ');

  // We check if the first element is bearer and we chek if the token has the correct format
  if ((tokenParse[0] == "bearer" || tokenParse[0] == "Bearer") && tokenParse[1].match(/\S+\.\S+\.\S+/) !== null) {
    try {
      // RS256 -> is the asymetric algorithm
      // we verify the token 
      const verification = jsonwebtoken.verify(tokenParse[1], PUB_KEY, { algorithms: ['RS256'] });
      // we create a property in the request object called "jwt" and it will have the payload information
      req.jwt = verification;
      // we pass to the next middleware
      next();
    } catch (e) {
      console.error(e)
      res.status(401).json({ success: false, msg: "You are not authorized to visit this route" });
    }

  } else {
    res.status(401).json({ success: false, msg: "You are not authorized to visit this route" });
  }
}

module.exports.validPassword = validPassword;
module.exports.genPassword = genPassword;
module.exports.issueJWT = issueJWT;
module.exports.authMiddleware = authMiddleware;