/**
 * Module dependencies.
 */
var util = require('util')
    , url = require('url')
    , merge = require('utils-merge')
    , OAuth2Strategy = require('passport-oauth2');


/**
 * `Strategy` constructor.
 *
 * The Bungie authentication strategy authenticates requests by delegating to
 * Bungie using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Bungie application's client id
 *   - `callbackURL`   URL to which CiscoSpark will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new BungieOAuth2Strategy({
 *         clientID: '123-456-789',
 *         callbackURL: 'https://www.example.net/auth/bungie/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    var defaultOptions = {
        authorizationURL: 'https://www.bungie.net/en/OAuth/Authorize',
        tokenURL: 'https://www.bungie.net/platform/app/oauth/token/',
        scopeSeparator: ',',
        customHeaders: {}
    };

    options = options || {};

    options.authorizationURL = options.authorizationURL || defaultOptions.authorizationURL;
    options.tokenURL = options.tokenURL || defaultOptions.tokenURL;

    options.scopeSeparator = options.scopeSeparator || defaultOptions.scopeSeparator;
    options.customHeaders = options.customHeaders || defaultOptions.customHeaders;

    OAuth2Strategy.call(this, options, verify);
    this.name = 'bungie-oauth2';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
        if (req.query.error == 'access_denied') {
            return this.fail({ message: req.query.error_description });
        } else {
            return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
        }
    }

    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
            // The callback URL is relative, resolve a fully qualified URL from the
            // URL of the originating request.
            callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
        }
    }

    var meta = {
        authorizationURL: this._oauth2._authorizeUrl,
        tokenURL: this._oauth2._accessTokenUrl,
        clientID: this._oauth2._clientId
    }

    if (req.query && req.query.code) {
        function loaded(err, ok, state) {
            if (err) { return self.error(err); }
            if (!ok) {
                return self.fail(state, 403);
            }

            var code = req.query.code;

            var params = self.tokenParams(options);
            params.grant_type = 'authorization_code';
            if (callbackURL) { params.redirect_uri = callbackURL; }

            self._oauth2.getOAuthAccessToken(code, params,
                function(err, accessToken, refreshToken, params) {
                    if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

                    self._loadUserProfile(params, function(err, profile) {
                        if (err) { return self.error(err); }

                        function verified(err, user, info) {
                            if (err) { return self.error(err); }
                            if (!user) { return self.fail(info); }

                            info = info || {};
                            if (state) { info.state = state; }
                            self.success(user, info);
                        }

                        try {
                            if (self._passReqToCallback) {
                                var arity = self._verify.length;
                                if (arity == 6) {
                                    self._verify(req, accessToken, refreshToken, params, profile, verified);
                                } else { // arity == 5
                                    self._verify(req, accessToken, refreshToken, profile, verified);
                                }
                            } else {
                                var arity = self._verify.length;
                                if (arity == 5) {
                                    self._verify(accessToken, refreshToken, params, profile, verified);
                                } else { // arity == 4
                                    self._verify(accessToken, refreshToken, profile, verified);
                                }
                            }
                        } catch (ex) {
                            return self.error(ex);
                        }
                    });
                }
            );
        }

        var state = req.query.state;
        try {
            var arity = this._stateStore.verify.length;
            if (arity == 4) {
                this._stateStore.verify(req, state, meta, loaded);
            } else { // arity == 3
                this._stateStore.verify(req, state, loaded);
            }
        } catch (ex) {
            return this.error(ex);
        }
    } else {
        var params = this.authorizationParams(options);
        params.response_type = 'code';
        if (callbackURL) { params.redirect_uri = callbackURL; }
        var scope = options.scope || this._scope;
        if (scope) {
            if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
            params.scope = scope;
        }

        var state = options.state;
        if (state) {
            params.state = state;

            var parsed = url.parse(this._oauth2._authorizeUrl, true);
            merge(parsed.query, params);
            parsed.query['client_id'] = this._oauth2._clientId;
            delete parsed.search;
            var location = url.format(parsed);
            this.redirect(location);
        } else {
            function stored(err, state) {
                if (err) { return self.error(err); }

                if (state) { params.state = state; }
                var parsed = url.parse(self._oauth2._authorizeUrl, true);
                merge(parsed.query, params);
                parsed.query['client_id'] = self._oauth2._clientId;
                delete parsed.search;
                var location = url.format(parsed);
                self.redirect(location);
            }

            try {
                var arity = this._stateStore.store.length;
                if (arity == 3) {
                    this._stateStore.store(req, meta, stored);
                } else { // arity == 2
                    this._stateStore.store(req, stored);
                }
            } catch (ex) {
                return this.error(ex);
            }
        }
    }
};


/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
OAuth2Strategy.prototype._loadUserProfile = function(params, done) {
    var self = this;

    function loadIt() {
        return self.userProfile(params.membership_id, done);
    }
    function skipIt() {
        return done(null);
    }

    if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
        // async
        this._skipUserProfile(params.access_token, function(err, skip) {
            if (err) { return done(err); }
            if (!skip) { return loadIt(); }
            return skipIt();
        });
    } else {
        var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
        if (!skip) { return loadIt(); }
        return skipIt();
    }
};


/**
 * Retrieve user profile from Bungie.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `membershipId`    the user's Bungie ID
 *
 * @param {String} membershipId
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(membershipId, done) {
    var profile = { membershipId: membershipId };
    done(null, profile);
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;