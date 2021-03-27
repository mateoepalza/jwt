const fs = require('fs');
const JwtStrategy = require('passport-jwt').Strategy;
// this is an object that allows us to specify how we should extract the jwt token from the header
const ExtractJwt  = require('passport-jwt').ExtractJwt;
const path = require('path');
const User = require('mongoose').model('User');



const pathToKey = path.join(__dirname, '..', 'id_rsa_pub.pem');
const PUB_KEY = fs.readFileSync(pathToKey, 'utf-8');

// This is the entire options object
/*
const passportJWTOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: PUB_KEY || secret phrase,
    issuer: "enter issuer here",
    audience: "enter audience here",
    algorithms: ['RS256'],
    ignoreExpiration: false,
    passReqToCallback: false,
    jsonWebTokenOptions: {
        complete: false,
        clockTolerance: '',
        maxAge: '2d',
        clockTimestamp: '100',
        nonce: 'string here for openID'
    }
}*/


/**
 * For the "fromAuthHeaderAsBearerToken()" passport will expect the token to come as follows:
 *  Authorization: Bearer <token>
 */
const options = {
    // This is the way on how we should extract the jwt from the http request (header, body, query parameters, authorization header, etc)
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    // Asymetric key or simetric key, in this case we are going to use the public key
    // we select the public key because we are configuring the verify piece
    secretOrKey: PUB_KEY,
    // Algorithm that we want to use
    algorithms: ['RS256']
};

// be aware that once we arrive to this point we already know that the JWT is valid
/**
 * Here the Strategy has already taken the JWT from the header
 * -> has already validated the JWT with the jsonwebtoken library
 * -> after being validated passes the payload so we can search for the user
 * -Z if the user is found, we return the user and the user is attached to the request object (req.user)
 */
const strategy = new JwtStrategy(options, (payload, done) =>{
    console.log("we get here");
    // Keep in mind that the payload has the "id" of the user, usually it is called "sub"
    User.findOne({_id: payload.sub })
        .then(user =>{
            console.log(user);
            // check if we got a user
           if(!user){
            return done(null, false);
           } 
           
           // we return the user
           return done(null, user);

        })
        .catch(err =>{
            done(err, null);
        })
})

module.exports = (passport) => {
    // passport is passed from the app.js that basically is the object that we get when we require passport 
    passport.use(strategy)   
}