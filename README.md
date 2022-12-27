# passport-jsonwebtoken

A passport strategy for authenticating via JWT and saving its contents.

## Install

`$ npm install passport-jsonwebtoken`

## Usage

### Configure Strategy

You'll have to include jsonwebtoken options when you create the strategy. The only hard requirement is a secret to sign the tokens with.

	const JsonWebTokenStrategy = require('passport-jsonwebtoken').Strategy;

	passport.use(new JsonWebTokenStrategy({secret: 'yoursecrethere'}, (payload, cb) => {
		let user;

		// Use the jwt payload to look up or build your user data.
		//

		cb(null, user);
	});

### Authentication

Authentication must be called as sessionless. This is a requirement by passport, so there's not much you can do to work around it.


	// Just makes life easier.
	const auth = () => passport.authenticate('jsonwebtoken', {session: false});

	app.get('/whatever', auth(), (req, res) => { ... });


User data will be stored in `req.user`. In addition, you can get the original jwt payload at `req.jwt`. No need to push it into the user data!
