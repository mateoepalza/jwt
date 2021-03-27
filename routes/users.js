const mongoose = require('mongoose');
const router = require('express').Router();   
const User = mongoose.model('User');
const passport = require('passport');
const utils = require('../lib/utils');

// we don't use sessions because we are using jwt's
router.get('/protected', passport.authenticate('jwt', {session: false}), (req, res, next) => {
    res.status(200).json({
        success: true,
        msg: 'You are authorized'
    })
});

// TODO
router.post('/login', function(req, res, next){
    // We search for the user in our database
    User.findOne({ username: req.body.username })
        .then( user => {
            // If the user doesn't exists
            if(!user){
                res.status(401).json({
                    success: false,
                    msg: "Could not find the user"
                })
            }
            
            // we validate the password
            const isValid = utils.validPassword(req.body.password, user.hash, user.salt);

            if(isValid){
                // generate the jwt token
                const tokenObject = utils.issueJWT(user);
                // response to the frontend
                res.status(200).json({
                    success: true,
                    user: user,
                    token: tokenObject.token,
                    expiresIn: tokenObject.expires,

                })
            }else{
                res.status(401).json({
                    success: false,
                    msg: "You entered the wrong password"
                })
            }
        })
        .catch( err =>{
            next(err);
        })
});

router.post('/register', function(req, res, next){
    // in here we obtain the hashed password and the salt random string 
    const saltHash = utils.genPassword(req.body.password);
    
    // deconstruct the object
    const salt = saltHash.salt;
    const hash = saltHash.hash;
    
    // we create a new instance of the user
    const newUser = new User({
        username: req.body.username,
        hash: hash,
        salt: salt
    });

    // We save in the database
    newUser.save()
        .then((user) => {

            // We issue the jwt tokew
            const jwt = utils.issueJWT(user)

            res.json({
                success: true, 
                user: user,
                token:jwt.token,
                expiresIn: jwt.expires
            })
        })
        .catch(err => next(err));
});

module.exports = router;