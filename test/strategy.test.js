const {expect} = require('chai');
const sinon = require('sinon');
const Strategy = require('../lib').Strategy;

const JWT_SECRET = 'jklasvnmkl3U890JAELRK3W0R98SJOAEFMjaklDJFKLDJFKLeiJLDKF';

// HS256, {userId: 1}
//
const GOOD_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlhdCI6MTY3MjE2NjExMH0.dvlDng4-bcr_Jy-ANdB49nO2_995FRXrrQXLDVHcOXs';

describe('Strategy', function() {
	describe('#ctor', function() {
		it('should throw exception if no verify callback', function() {
			expect(() => new Strategy({})).to.throw();
		});

		it('should throw exception if no secret in options', function() {
			expect(() => new Strategy(() => {})).to.throw();
		});

		it('should set up internal variables based on options', function() {
			const verify = () => {};
			const options = {secret: 'abc', passReqToCallback: true, a: 1};
			const strategy = new Strategy(options, verify);

			expect(strategy.name).to.eql('jsonwebtoken');
			expect(strategy.verify).to.eql(verify);
			expect(strategy.passReqToCallback).to.eql(options.passReqToCallback);
			expect(strategy.secret).to.eql(options.secret);

			const jwtOptions = {...options};
			delete jwtOptions.secret;
			delete jwtOptions.passReqToCallback;
			expect(strategy.jwtOptions).to.eql(jwtOptions);
		});

		it('should create a passport Strategy instance', function() {
			const strategy = new Strategy({secret: '1'}, () => {});
			expect(strategy).to.be.instanceOf(Strategy);
		});
	});

	describe('#parseAuthHeader', function() {
		let strategy;

		beforeEach(function() {
			strategy = new Strategy({secret: 'abc'}, () => {});
		});

		it('should return null if no auth header', function() {
			const result = strategy.parseAuthHeader({headers: {}});
			expect(result).to.be.null;
		});

		it('should return null if no token', function() {
			const result = strategy.parseAuthHeader({headers: {
				authorization: 'BadAuth'
			}});
			expect(result).to.be.null;
		});

		it('should return null if not a Bearer authorization', function() {
			const result = strategy.parseAuthHeader({headers: {
				authorization: 'BadAuth abc123'
			}});
			expect(result).to.be.null;
		});

		it('should return token on success', function() {
			const result = strategy.parseAuthHeader({headers: {
				authorization: 'Bearer 123'
			}});
			expect(result).to.eql('123');
		});
	});

	describe('#authenticate', function() {
		it('should call fail if no token', async function() {
			const strategy = new Strategy({secret: JWT_SECRET}, () => {});
			strategy.fail = sinon.spy();
			await strategy.authenticate({headers: {}});

			sinon.assert.calledOnce(strategy.fail);
		});

		it('should call fail if token verify fails', async function() {
			const strategy = new Strategy({secret: JWT_SECRET}, () => {});
			strategy.fail = sinon.spy();
			await strategy.authenticate({headers: {authorization: 'Bearer badtoken'}});

			sinon.assert.calledOnce(strategy.fail);
		});

		it('should call error if verified passes an error', async function() {
			const verify = (payload, verified) => verified('Error');
			const strategy = new Strategy({secret: JWT_SECRET}, verify);
			strategy.error = sinon.spy();
			await strategy.authenticate({headers: {authorization: 'Bearer ' + GOOD_JWT}});

			sinon.assert.calledOnce(strategy.error);
		});

		it('should call fail if no user is passed to verification', async function() {
			const verify = (payload, verified) => verified();
			const strategy = new Strategy({secret: JWT_SECRET}, verify);
			strategy.fail = sinon.spy();
			await strategy.authenticate({headers: {authorization: 'Bearer ' + GOOD_JWT}});

			sinon.assert.calledOnce(strategy.fail);
		});

		it('should call success with user if user is passed to verification', async function() {
			const verify = (payload, verified) => verified(null, {});
			const strategy = new Strategy({secret: JWT_SECRET}, verify);
			strategy.success = sinon.spy();
			await strategy.authenticate({headers: {authorization: 'Bearer ' + GOOD_JWT}});

			sinon.assert.calledOnce(strategy.success);
		});

		it('should set JWT payload if user is passed to verification', async function() {
			const req = {headers: {authorization: 'Bearer ' + GOOD_JWT}};
			const verify = (payload, verified) => verified(null, {});
			const strategy = new Strategy({secret: JWT_SECRET}, verify);
			strategy.success = () => {};
			await strategy.authenticate(req);

			expect(req.jwt.userId).to.eql(1);
		});

		it('should take jwt options from constructor', async function() {
			const req = {headers: {authorization: 'Bearer ' + GOOD_JWT}};
			const verify = (payload, verified) => verified(null, {});
			const strategy = new Strategy({secret: JWT_SECRET, algorithms: 'HS512'}, verify);
			strategy.fail = sinon.spy();
			await strategy.authenticate(req);

			sinon.assert.calledOnce(strategy.fail);
		});
	});
});
