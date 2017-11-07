const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const User = require('../models/users');
const config = require('../config/database');

module.exports = function(passport) {
    var opts = {};

    opts.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('jwt');
    opts.secretOrKey = config.secret;

    passport.use(new JwtStrategy(opts, function(jwt_payload, done) {
        console.log(jwt_payload);
        User.findOne({id: jwt_payload._doc.id}, function(err, user) {
            if (err) {
                console.log("a");
                return done(err, false);
            }
            if (user) {
                console.log("b");
                return done(null, user);
            } else {
                console.log("c");
                return done(null, false);
            }
        });
    }));
}