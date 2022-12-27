const request = require('supertest');
const express = require('express');
const passport = require('passport');
const JwtStrategy = require('../lib');
const {expect} = require('chai');

const JWT_SECRET = 'ajfk;l903AJIFKJLDFMAL;KD,FAJ3FKL;jkda;slkf';

// HS256, {userId: 1}
//
const JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlhdCI6MTY3MjE2OTQxNn0.jGcmJlnIa4-ZU_RbDwkO8OYqGsDpCiEz-5XmMfIURXQ';

// Makes things easier to understand.
//
const authenticate = () => passport.authenticate('jsonwebtoken', {session: false});

passport.use(new JwtStrategy({secret: JWT_SECRET}, function(payload, cb) {
	cb(null, {userId: payload.userId});
}));

const app = express();
app.get('/', authenticate(), (req, res) => {
	res.send(req.user);
});

describe('Integration', function() {
	beforeEach(function() {
		delete error;
		delete user;
	});

	it('should reject bad tokens with 401', function() {
		request(app)
			.get('/')
			.expect(401)
			.end(function (err, res) {
				if (err) throw err;
			});
	});

	it('should accept good tokens with 200', function() {
		request(app)
			.get('/')
			.set('Authorization', 'Bearer ' + JWT_TOKEN)
			.expect(200, {userId: 1})
			.end(function (err, res) {
				if (err) throw err;
			});
	});
});
