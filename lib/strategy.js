const crypto = require('crypto');
const passport = require('passport-strategy');
const util = require('util');
const url = require('url');
const jwt = require('jsonwebtoken');

const DRIFT_WINDOW_MINUTES = 1;
const RGX_AUTH_METHOD = /^[^ ]+ +/;
const RGX_HMAC_AUTH = /^([^ ]+) +([^:]+):([^ ]+) *$/;

function Strategy(options, verify) {
    // Shift parameters if optional ones are excluded
    if (!verify) {
        verify = options;
        options = {};
    }
    if (typeof verify !== 'function')
        throw new TypeError('Verify callback is required.');

	// Throw exception if no secret is included.
	if (!options.secret)
		throw new TypeError('"secret" is a required option.');
    
    // call super()
    passport.Strategy.call(this);

    // set up fields
    this.name = 'jsonwebtoken';
    this.verify = verify;
    this.passReqToCallback = options.passReqToCallback;
	this.secret = options.secret;

	// Save JWT options
	const jwtOptions = {...options};
	delete jwtOptions.secret;
	delete jwtOptions.passReqToCallback;
	this.jwtOptions = jwtOptions;
}
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.parseAuthHeader = function(req) {
    if (!req.headers.authorization)
		return null;

	const tokens = req.headers.authorization.split(' ');
	if (tokens.length < 2 || tokens[0] !== 'Bearer')
		return null;

	return tokens[1];
};

Strategy.prototype.authenticate = async function(req, options) {
    const _this = this;
    options = options || {};

    let token = this.parseAuthHeader(req);
    if (!token)
        return this.fail(options.badRequestMessage || 'Bad Authorization header.');

	let payload;
	try {
		payload = jwt.verify(token, this.secret, this.jwtOptions);
	}
	catch(e) {
		return this.fail(options.badRequestMessage || 'Bad JWT token.');
	}

    let verified = function (err, user, info) {
        if (err)
			return _this.error(err);
        if (!user)
            return _this.fail(options.badRequestMessage || 'Bad credentials.');

		req.jwt = payload;
        _this.success(user, info);
    };

    try {
        if (this.passReqToCallback)
            this.verify(req, payload, verified);
        else
            this.verify(payload, verified);
    }
    catch (e) {
        return this.error(e);
    }
};

module.exports = Strategy;
