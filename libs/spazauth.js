/**
 * A library for performing authentication.
 * Currently supports both Basic and oAuth.
 */
/**
 * @constant 
 */
var SPAZCORE_AUTHTYPE_BASIC  = 'basic';
/**
 * @constant 
 */
var SPAZCORE_AUTHTYPE_OAUTH  = 'oauth';

/**
 * @constant 
 */
var SPAZAUTH_SERVICES = {};

SPAZAUTH_SERVICES[SPAZCORE_ACCOUNT_STATUSNET] = {
	'authType': SPAZCORE_AUTHTYPE_BASIC
};
SPAZAUTH_SERVICES[SPAZCORE_ACCOUNT_TUMBLR_TWITTER] = {
	'authType': SPAZCORE_AUTHTYPE_BASIC
};
SPAZAUTH_SERVICES[SPAZCORE_ACCOUNT_WORDPRESS_TWITTER] = {
	'authType': SPAZCORE_AUTHTYPE_BASIC
};
SPAZAUTH_SERVICES[SPAZCORE_ACCOUNT_IDENTICA] = {
    'authType': SPAZCORE_AUTHTYPE_BASIC
};
SPAZAUTH_SERVICES[SPAZCORE_ACCOUNT_FREELISHUS] = {
    'authType': SPAZCORE_AUTHTYPE_BASIC
};
SPAZAUTH_SERVICES[SPAZCORE_ACCOUNT_CUSTOM] = {
    'authType': SPAZCORE_AUTHTYPE_BASIC
};
SPAZAUTH_SERVICES['default'] = {
	'authType': SPAZCORE_AUTHTYPE_BASIC
};

/**
 * Construct a new authentication object.
 *
 * @param {string} service name of the service to authenticate (ex: twitter, identica)
 * @class SpazAuth
 * @constructor
 */
function SpazAuth(service) {
    var serviceInfo = SPAZAUTH_SERVICES[service];
    if (serviceInfo == undefined) {
        sch.error("Invalid authentication service: " + service);
        return null;
    }

    switch (serviceInfo.authType) {
        case SPAZCORE_AUTHTYPE_OAUTH:
            return new SpazOAuth(service, serviceInfo);
        case SPAZCORE_AUTHTYPE_BASIC:
            return new SpazBasicAuth();
        default:
            return new SpazBasicAuth();
    }
};

/**
 * use this to add services that aren't in by default (like, say, stuff with secrets)
 */
SpazAuth.addService = function(label, opts) {
    SPAZAUTH_SERVICES[label] = opts;
};



/**
 * Construct a new basic authentication object.
 *
 * @class SpazBasicAuth
 * @constructor
 */
function SpazBasicAuth() {
};

/**
 * Set username and password of account to access service.
 *
 * @param {string} username
 * @param {string} password
 * @param {function} [onComplete] a callback to fire when complete. Currently just passed TRUE all the time; for compatibility with oAuth need for callbacks
 * @return {Boolean} true. ALWAYS returns true!
 */
SpazBasicAuth.prototype.authorize = function(username, password, onComplete) {
    this.username = username;
    this.password = password;
    this.authHeader = "Basic " + sc.helpers.Base64.encode(username + ":" + password);
    
    if (onComplete) {
        onComplete.call(this, true);
    }
	return true;
};


/**
 * Returns the authentication header
 * @returns {string} Authentication header value
 */
SpazBasicAuth.prototype.signRequest = function() {
    return this.authHeader;
};

/**
  * Load basic auth credentials from a serialized string
  *
  * @param {string} pickle the serialized data string returned by save()
  * @returns {boolean} true if successfully loaded
  */
SpazBasicAuth.prototype.load = function(pickle) {
    var credentials = pickle.split(':', 2);
    if (credentials.length != 2) {
        sch.error("Invalid basic auth pickle: " + pickle);
        return false;
    }

    this.authorize(credentials[0], credentials[1]);
    return true;
};

/**
  * Save basic auth credentials into a serialized string
  *
  * @returns {string} serialized string
  */
SpazBasicAuth.prototype.save = function() {
    return this.username + ":" + this.password;
};


SpazBasicAuth.prototype.getUsername = function() {
	return this.username;
};

SpazBasicAuth.prototype.getPassword = function() {
	return this.password;
};


/**
 * Construct a new OAuth authentication object.
 *
 * @param {string} realm
 * @param {object} options
 * @class SpazOAuth
 * @constructor
 */
function SpazOAuth(realm, options) {
    this.realm = realm;
    this.opts = options;
};

SpazOAuth.prototype._fetchToken = function(url, onComplete, onError) {
    var message = {
        method: 'POST',
        action: url,
        parameters: {}
    }

    OAuth.completeRequest(message, this.opts);

    jQuery.ajax({
        type: 'POST',
        url: url,
        data: message.parameters,
        dataType: 'text',
        success: function (data) {
            var decodedData = OAuth.decodeForm(data);
            onComplete(OAuth.getParameter(decodedData, 'oauth_token'),
                       OAuth.getParameter(decodedData, 'oauth_token_secret'));
        },
        error: function(xhr, textStatus, errorThrown) {
            onError(xhr.responseText);
        },
        beforeSend: function(xhr) {
            xhr.setRequestHeader('Cookie', '');
        }
    });
};

/**
 * Generate an authorization URL to redirect user so they can
 * authorize us access to their account.
 *
 * @param {function} [onComplete] a callback fired to supply the authorization URL once the request token is fetched.
 * @param {function} [onError] a callback fired if we failed to fetch a request token.
 */
SpazOAuth.prototype.getAuthorizationURL = function(onComplete, onError) {
    var self = this;

    // Callback for providing authorization URL once we have the request token.
    function createAuthorizationURL(token, secret) {
        // We will need the request token later when we fetch the access token.
        self.requestToken = [token, secret];

        // Create the authorization URL by append the oauth_token to the end.
        var url = self.opts.authorizationURL + '?oauth_token=' + token;
        onComplete(url);
    }

    // Fetch a request token from the service provider.
    this._fetchToken(this.opts.requestURL, createAuthorizationURL, onError);
};

/**
 * Authorize access to the service by fetching an OAuth access token.
 * 
 * @param {string} provide the oauth_verifier value if provided by the user or callback from the service provider.
 * @param {function} [onComplete] a callback to fire on complete.
 * @param {function} [onError] a callback for when we fail to fetch the access token.
 */
SpazOAuth.prototype.authorize = function() {
    var verifier, onComplete, onError;
    if (arguments.length > 2) {
        verifier = arguments[0];
        onComplete = arguments[1];
        onError = arguments[2];
    } else {
        verifier = null;
        onComplete = arguments[0];
        onError = arguments[1];
    }

    var self = this;

    function success(token, secret) {
        self.setAccessToken(token, secret);
        onComplete();
    }

    // Attempt to request an access token from the service provider.
    this._fetchToken(this.opts.accessURL, success, onError);
};


/**
  * Set the access token
  *
  * @param {string} key
  * @param {string} secret
  */
SpazOAuth.prototype.setAccessToken = function(key, secret) {
    this.accessToken = {key: key, secret: secret};
    this.signingCredentials = {
        consumerKey: this.opts.consumerKey,
        consumerSecret: this.opts.consumerSecret,
        token: key,
        tokenSecret: secret
    };
};

/**
 * Sign a HTTP request and return oAuth header
 *
 * @param {string} method HTTP method of the request
 * @param {string} url the URL of the request
 * @param {object} parameters map of all parameters in the request
 * @returns {string} Authorization header value
 */
SpazOAuth.prototype.signRequest = function(method, url, parameters) {
    // We need to copy parameters because OAuth.js modifies it.
    var param = jQuery.extend({}, parameters);

    OAuth.completeRequest({
        method: method,
        action: url,
        parameters: param
    }, this.signingCredentials);

    return OAuth.getAuthorizationHeader(this.realm, param);
};

/**
  * Load OAuth credentials from a serialized string
  *
  * @param {string} pickle the serialized string returned by save()
  * @returns {boolean} true if successfully loaded
  */
SpazOAuth.prototype.load = function(pickle) {
    var credentials = pickle.split(':', 3);
    if (credentials.length != 3) {
        sch.error("Invalid oauth pickle: " + pickle);
        return false;
    }

    this.username = credentials[0];
    this.setAccessToken(credentials[1], credentials[2]);
    return true;
};

/**
  * Save OAuth credentials to a serialized string
  *
  * @returns {string} serialized string
  */
SpazOAuth.prototype.save = function() {
    return this.username + ":" + this.accessToken.key + ":" + this.accessToken.secret;
};

