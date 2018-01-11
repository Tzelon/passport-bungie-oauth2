# Passport-Bungie-OAuth2
[Passport](http://passportjs.org/) strategy for authenticating with [Bungie](https://bungie.net/)
using the OAuth 2.0 API.

This module lets you authenticate using Bungie in your Node.js applications.
By plugging into Passport, Bungie authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install
    $ npm install passport-bungie-oauth2

## Usage
### Configure Strategy

The Bungie authentication strategy authenticates users using a Bungie account
and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which accepts
these credentials and calls `done` providing client ID, and callback URL. The library.

    passport.use(new BungieOAuth2Strategy({
        clientID: BUNGIE_CLIENT_ID,
        callbackURL: "https://www.example.net/auth/dropbox-oauth2/callback"
      },
      function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ membershipId: profile.membershipId }, function (err, user) {
          return done(err, user);
        });
      }
    ));

### Authenticate Requests
Use `passport.authenticate()`, specifying the `'bungie-oauth2'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/bungie',
      passport.authenticate('dropbox-bungie'));

    app.get('/auth/bungie/callback', 
      passport.authenticate('bungie-oauth2', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Examples
Examples not yet provided

## Tests
Tests not yet provided


## Prior work
This strategy is based on Jared Hanson's GitHub strategy for passport: [Jared Hanson](http://github.com/jaredhanson)

## License
licensed under the MIT license.

Copyright (c) 2017-2018 Tzelon Machluf
