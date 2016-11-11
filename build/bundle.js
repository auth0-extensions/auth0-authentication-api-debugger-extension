module.exports =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "/build/";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var Webtask = __webpack_require__(1);

	// This is the entry-point for the Webpack build. We need to convert our module
	// (which is a simple Express server) into a Webtask-compatible function.
	module.exports = Webtask.fromExpress(__webpack_require__(2));

/***/ },
/* 1 */
/***/ function(module, exports) {

	module.exports = require("webtask-tools");

/***/ },
/* 2 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var path = __webpack_require__(3);
	var crypto = __webpack_require__(4);
	var express = __webpack_require__(5);
	var bodyParser = __webpack_require__(6);
	var handlebars = __webpack_require__(7);
	var Webtask = __webpack_require__(1);
	var expressTools = __webpack_require__(8);
	var metadata = __webpack_require__(30);

	var utils = __webpack_require__(31);
	var index = handlebars.compile(__webpack_require__(104));
	var partial = handlebars.compile(__webpack_require__(105));

	var app = express();
	app.use(bodyParser.json());
	app.use(bodyParser.urlencoded({ extended: false }));

	app.get('/pkce', function (req, res) {
	  var verifier = utils.base64url(crypto.randomBytes(32));
	  return res.json({
	    verifier: verifier,
	    verifier_challenge: utils.base64url(crypto.createHash('sha256').update(verifier).digest())
	  });
	});

	app.get('/hash', function (req, res) {
	  res.send(partial({
	    hash: utils.syntaxHighlight(req.query),
	    id_token: utils.jwt(req.query && req.query.id_token),
	    access_token: utils.jwt(req.query && req.query.access_token)
	  }));
	});

	app.post('/request', function (req, res) {
	  var request = req.body.request;
	  delete req.body.request;
	  res.send(partial({
	    request: utils.syntaxHighlight(request),
	    response: utils.syntaxHighlight(req.body),
	    id_token: utils.jwt(req.body && req.body.id_token),
	    access_token: utils.jwt(req.body && req.body.access_token)
	  }));
	});

	app.get('/meta', function (req, res) {
	  res.status(200).send(metadata);
	});

	var renderIndex = function renderIndex(req, res) {
	  try {
	    var headers = req.headers;
	    delete headers['x-wt-params'];

	    res.send(index({
	      method: req.method,
	      baseUrl: expressTools.urlHelpers.getBaseUrl(req).replace('http://', 'https://'),
	      headers: utils.syntaxHighlight(req.headers),
	      body: utils.syntaxHighlight(req.body),
	      query: utils.syntaxHighlight(req.query),
	      authorization_code: req.query && req.query.code,
	      samlResponse: utils.samlResponse(req.body && req.body.SAMLResponse),
	      wsFedResult: utils.wsFedResult(req.body && req.body.wresult),
	      id_token: utils.jwt(req.body && req.body.id_token),
	      access_token: utils.jwt(req.body && req.body.access_token)
	    }));
	  } catch (e) {
	    console.log(e);
	    res.json(e);
	  }
	};

	app.get('*', renderIndex);
	app.post('*', renderIndex);

	module.exports = app; //Webtask.fromExpress(app);

/***/ },
/* 3 */
/***/ function(module, exports) {

	module.exports = require("path");

/***/ },
/* 4 */
/***/ function(module, exports) {

	module.exports = require("crypto");

/***/ },
/* 5 */
/***/ function(module, exports) {

	module.exports = require("express");

/***/ },
/* 6 */
/***/ function(module, exports) {

	module.exports = require("body-parser");

/***/ },
/* 7 */
/***/ function(module, exports) {

	module.exports = require("handlebars");

/***/ },
/* 8 */
/***/ function(module, exports, __webpack_require__) {

	const server = __webpack_require__(9);
	const urlHelpers = __webpack_require__(11);
	const middlewares = __webpack_require__(13);
	const routes = __webpack_require__(28);

	/*
	 * Bootstrap function to run initialize an Express server.
	 */
	module.exports.createServer = server.createServer;

	/*
	 * Helpers to figure out the full url and the base path based on the request
	 */
	module.exports.urlHelpers = urlHelpers;

	/*
	 * Useful middlewares
	 */
	module.exports.middlewares = middlewares;

	/*
	 * Route bundles.
	 */
	module.exports.routes = routes;


/***/ },
/* 9 */
/***/ function(module, exports, __webpack_require__) {

	const tools = __webpack_require__(10);
	const Webtask = __webpack_require__(1);

	module.exports.createServer = function(cb) {
	  const serverFn = tools.createServer(cb);
	  let dispatchFn = null;

	  return Webtask.fromExpress(function requestHandler(req, res) {
	    if (!dispatchFn) {
	      dispatchFn = serverFn(req.webtaskContext);
	    }

	    return dispatchFn(req, res);
	  });
	};


/***/ },
/* 10 */
/***/ function(module, exports) {

	module.exports = require("auth0-extension-tools");

/***/ },
/* 11 */
/***/ function(module, exports, __webpack_require__) {

	const url = __webpack_require__(12);

	const getBasePath = function(originalUrl, path) {
	  var basePath = url.parse(originalUrl).pathname || '';
	  basePath = basePath.replace(path, '')
	    .replace(/^\/|\/$/g, '');
	  if (!basePath.startsWith('/')) {
	    basePath = '/' + basePath;
	  }
	  if (!basePath.endsWith('/')) {
	    basePath += '/';
	  }
	  return basePath;
	};

	module.exports.getBasePath = function(req) {
	  return getBasePath(req.originalUrl || '', req.path);
	};

	module.exports.getBaseUrl = function(req) {
	  const originalUrl = url.parse(req.originalUrl || '').pathname || '';
	  return url.format({
	    protocol: process.env.NODE_ENV !== 'production' ? 'http' : 'https',
	    host: req.get('host'),
	    pathname: originalUrl.replace(req.path, '')
	  });
	};


/***/ },
/* 12 */
/***/ function(module, exports) {

	module.exports = require("url");

/***/ },
/* 13 */
/***/ function(module, exports, __webpack_require__) {

	module.exports.authenticateAdmins = __webpack_require__(14);
	module.exports.authenticateUsers = __webpack_require__(21);
	module.exports.requireAuthentication = __webpack_require__(23);
	module.exports.errorHandler = __webpack_require__(24);
	module.exports.managementApiClient = __webpack_require__(25);
	module.exports.validateHookToken = __webpack_require__(26);
	module.exports.webtaskConfig = __webpack_require__(27);


/***/ },
/* 14 */
/***/ function(module, exports, __webpack_require__) {

	const decode = __webpack_require__(15);
	const expressJwt = __webpack_require__(18);
	const tools = __webpack_require__(10);
	const conditional = __webpack_require__(19);

	module.exports = function(options) {
	  if (!options || typeof options !== 'object') {
	    throw new tools.ArgumentError('Must provide the options');
	  }

	  if (options.secret === null || options.secret === undefined) {
	    throw new tools.ArgumentError('Must provide a valid secret');
	  }

	  if (typeof options.secret !== 'string' || options.secret.length === 0) {
	    throw new tools.ArgumentError('The provided secret is invalid: ' + options.secret);
	  }

	  if (options.audience === null || options.audience === undefined) {
	    throw new tools.ArgumentError('Must provide a valid secret');
	  }

	  if (typeof options.audience !== 'string' || options.audience.length === 0) {
	    throw new tools.ArgumentError('The provided audience is invalid: ' + options.audience);
	  }

	  if (options.baseUrl === null || options.baseUrl === undefined) {
	    throw new tools.ArgumentError('Must provide a valid base URL');
	  }

	  if (typeof options.baseUrl !== 'string' || options.baseUrl.length === 0) {
	    throw new tools.ArgumentError('The provided base URL is invalid: ' + options.baseUrl);
	  }

	  const validateToken = expressJwt({
	    audience: options.audience,
	    issuer: options.baseUrl,
	    secret: options.secret,
	    algorithms: [ 'HS256' ],
	    credentialsRequired: options.credentialsRequired || true
	  });

	  return function(req, res, next) {
	    validateToken(req, res, function(err) {
	      if (err) {
	        return next(err);
	      }

	      if (options.onLoginSuccess) {
	        return options.onLoginSuccess(req, res, next);
	      }

	      return next();
	    });
	  };
	};

	module.exports.optional = function(options) {
	  const mw = module.exports(options);
	  return conditional(
	    function(req) {
	      if (req && req.headers && req.headers.authorization && req.headers.authorization.indexOf('Bearer ') === 0) {
	        try {
	          const decodedToken = decode(req.headers.authorization.split(' ')[1]);
	          return decodedToken && decodedToken.iss === options.baseUrl;
	        } catch (ex) {
	          return false;
	        }
	      }

	      return false;
	    },
	    mw
	  );
	};


/***/ },
/* 15 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var base64_url_decode = __webpack_require__(16);

	module.exports = function (token,options) {
	  if (typeof token !== 'string') {
	    throw new Error('Invalid token specified');
	  }

	  options = options || {};
	  var pos = options.header === true ? 0 : 1;
	  return JSON.parse(base64_url_decode(token.split('.')[pos]));
	};


/***/ },
/* 16 */
/***/ function(module, exports, __webpack_require__) {

	var atob = __webpack_require__(17);

	function b64DecodeUnicode(str) {
	  return decodeURIComponent(atob(str).replace(/(.)/g, function (m, p) {
	    var code = p.charCodeAt(0).toString(16).toUpperCase();
	    if (code.length < 2) {
	      code = '0' + code;
	    }
	    return '%' + code;
	  }));
	}

	module.exports = function(str) {
	  var output = str.replace(/-/g, "+").replace(/_/g, "/");
	  switch (output.length % 4) {
	    case 0:
	      break;
	    case 2:
	      output += "==";
	      break;
	    case 3:
	      output += "=";
	      break;
	    default:
	      throw "Illegal base64url string!";
	  }

	  try{
	    return b64DecodeUnicode(output);
	  } catch (err) {
	    return atob(output);
	  }
	};


/***/ },
/* 17 */
/***/ function(module, exports) {

	/**
	 * The code was extracted from:
	 * https://github.com/davidchambers/Base64.js
	 */

	var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

	function InvalidCharacterError(message) {
	  this.message = message;
	}

	InvalidCharacterError.prototype = new Error();
	InvalidCharacterError.prototype.name = 'InvalidCharacterError';

	function polyfill (input) {
	  var str = String(input).replace(/=+$/, '');
	  if (str.length % 4 == 1) {
	    throw new InvalidCharacterError("'atob' failed: The string to be decoded is not correctly encoded.");
	  }
	  for (
	    // initialize result and counters
	    var bc = 0, bs, buffer, idx = 0, output = '';
	    // get next character
	    buffer = str.charAt(idx++);
	    // character found in table? initialize bit storage and add its ascii value;
	    ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer,
	      // and if not first of each 4 characters,
	      // convert the first 8 bits to one ascii character
	      bc++ % 4) ? output += String.fromCharCode(255 & bs >> (-2 * bc & 6)) : 0
	  ) {
	    // try to find character in table (0-63, not found => -1)
	    buffer = chars.indexOf(buffer);
	  }
	  return output;
	}


	module.exports = typeof window !== 'undefined' && window.atob && window.atob.bind(window) || polyfill;


/***/ },
/* 18 */
/***/ function(module, exports) {

	module.exports = require("express-jwt");

/***/ },
/* 19 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	const once = __webpack_require__(20);

	/**
	 * Returns a middleware that can be used to conditionally execute another
	 * middleware, or alternatively bypass it.
	 *
	 * @param {(boolean|function)} condition
	 *   If true, the middleware will be executed, else the next middleware will be
	 *   executed. If the conddition is a function it will be executed with the req,
	 *   res, and next arguments. The return of the function will be used as the
	 *   conditional.
	 * @param {function} success
	 *   The middleware to conditionally execute if condition is true.
	 * @param {function} fail
	 *   The middleware to conditionally execute if condition is false.
	 *
	 * @return {function}
	 *   A middleware wraper to conditionally execute another middleware.
	 *
	 * @example
	 *   // Will enable middleware for requests that use the application/json accept
	 *   // header.
	 *   app.use(require('express-conditional')(
	 *     function (req, res, next) {
	 *       return req.get('accept') === 'application/json';
	 *     },
	 *     function (req, res, next) {
	 *       next();
	 *     }
	 *  ));
	 */
	module.exports = (condition, success, fail) => (req, res, next) => {
	  const nextOnce = once(next);
	  if (condition === true || (typeof condition === 'function' && condition(req, res, nextOnce))) {
	    return success(req, res, nextOnce);
	  }
	  if (fail) {
	    return fail(req, res, nextOnce);
	  }

	  return nextOnce();
	};



/***/ },
/* 20 */
/***/ function(module, exports) {

	module.exports = require("once");

/***/ },
/* 21 */
/***/ function(module, exports, __webpack_require__) {

	const decode = __webpack_require__(15);
	const jwt = __webpack_require__(18);
	const jwksRsa = __webpack_require__(22);
	const tools = __webpack_require__(10);
	const conditional = __webpack_require__(19);
	const UnauthorizedError = __webpack_require__(10).UnauthorizedError;

	module.exports = function(options) {
	  if (!options || typeof options !== 'object') {
	    throw new tools.ArgumentError('Must provide the options');
	  }

	  if (options.domain === null || options.domain === undefined) {
	    throw new tools.ArgumentError('Must provide a valid domain');
	  }

	  if (typeof options.domain !== 'string' || options.domain.length === 0) {
	    throw new tools.ArgumentError('The provided domain is invalid: ' + options.domain);
	  }

	  if (options.audience === null || options.audience === undefined) {
	    throw new tools.ArgumentError('Must provide a valid audience');
	  }

	  if (typeof options.audience !== 'string' || options.audience.length === 0) {
	    throw new tools.ArgumentError('The provided audience is invalid: ' + options.audience);
	  }

	  const validateToken = jwt({
	    secret: jwksRsa.expressJwtSecret({
	      cache: true,
	      rateLimit: true,
	      jwksRequestsPerMinute: 5,
	      jwksUri: 'https://' + options.domain + '/.well-known/jwks.json',
	      handleSigningKeyError: function(err, cb) {
	        if (err instanceof jwksRsa.SigningKeyNotFoundError) {
	          return cb(new UnauthorizedError('A token was provided with an invalid kid'));
	        }

	        return cb(err);
	      }
	    }),

	    // Validate the audience and the issuer.
	    audience: options.audience,
	    issuer: 'https://' + options.domain + '/',
	    algorithms: [ 'RS256' ],

	    // Optionally require authentication
	    credentialsRequired: (options && options.credentialsRequired) || true
	  });

	  return function(req, res, next) {
	    validateToken(req, res, function(err) {
	      if (err) {
	        return next(err);
	      }

	      if (options.onLoginSuccess) {
	        return options.onLoginSuccess(req, res, next);
	      }

	      return next();
	    });
	  };
	};

	module.exports.optional = function(options) {
	  const mw = module.exports(options);
	  return conditional(
	    function(req) {
	      if (req && req.headers && req.headers.authorization && req.headers.authorization.indexOf('Bearer ') === 0) {
	        try {
	          const decodedToken = decode(req.headers.authorization.split(' ')[1]);
	          return decodedToken && decodedToken.iss === 'https://' + options.domain + '/';
	        } catch (ex) {
	          return false;
	        }
	      }

	      return false;
	    },
	    mw
	  );
	};


/***/ },
/* 22 */
/***/ function(module, exports) {

	module.exports = require("jwks-rsa");

/***/ },
/* 23 */
/***/ function(module, exports, __webpack_require__) {

	const UnauthorizedError = __webpack_require__(10).UnauthorizedError;

	module.exports = function(req, res, next) {
	  if (!req.user) {
	    return next(new UnauthorizedError('Authentication required for this endpoint.'));
	  }

	  return next();
	};


/***/ },
/* 24 */
/***/ function(module, exports) {

	module.exports = function(errorLogger) {
	  return function(err, req, res, next) {
	    if (errorLogger) {
	      errorLogger(err);
	    }

	    if (err && err.status) {
	      res.status(err.status);
	      return res.json({
	        error: err.code || err.name,
	        message: err.message || err.name
	      });
	    }

	    res.status(err.status || 500);
	    if (process.env.NODE_ENV === 'production') {
	      return res.json({
	        error: 'InternalServerError',
	        message: err.message || err.name
	      });
	    }

	    return res.json({
	      error: 'InternalServerError',
	      message: err.message || err.name,
	      details: {
	        message: err.message,
	        status: err.status,
	        stack: err.stack
	      }
	    });
	  };
	};


/***/ },
/* 25 */
/***/ function(module, exports, __webpack_require__) {

	const tools = __webpack_require__(10);

	module.exports = function(handlerOptions) {
	  return function(req, res, next) {
	    const request = req;
	    const isAdministrator = req.user && req.user.access_token && req.user.access_token.length;
	    const options = !isAdministrator ? handlerOptions : {
	      domain: handlerOptions.domain,
	      accessToken: req.user.access_token
	    };

	    tools.managementApi.getClient(options)
	      .then(function(auth0) {
	        request.auth0 = auth0;
	        next();
	        return null;
	      })
	      .catch(function(err) {
	        next(err);
	      });
	  };
	};


/***/ },
/* 26 */
/***/ function(module, exports, __webpack_require__) {

	const tools = __webpack_require__(10);

	module.exports = function(domain, webtaskUrl, extensionSecret) {
	  if (domain === null || domain === undefined) {
	    throw new tools.ArgumentError('Must provide the domain');
	  }

	  if (typeof domain !== 'string' || domain.length === 0) {
	    throw new tools.ArgumentError('The provided domain is invalid: ' + domain);
	  }

	  if (webtaskUrl === null || webtaskUrl === undefined) {
	    throw new tools.ArgumentError('Must provide the webtaskUrl');
	  }

	  if (typeof webtaskUrl !== 'string' || webtaskUrl.length === 0) {
	    throw new tools.ArgumentError('The provided webtaskUrl is invalid: ' + webtaskUrl);
	  }

	  if (extensionSecret === null || extensionSecret === undefined) {
	    throw new tools.ArgumentError('Must provide the extensionSecret');
	  }

	  if (typeof extensionSecret !== 'string' || extensionSecret.length === 0) {
	    throw new tools.ArgumentError('The provided extensionSecret is invalid: ' + extensionSecret);
	  }

	  return function(hookPath) {
	    if (hookPath === null || hookPath === undefined) {
	      throw new tools.ArgumentError('Must provide the hookPath');
	    }

	    if (typeof hookPath !== 'string' || hookPath.length === 0) {
	      throw new tools.ArgumentError('The provided hookPath is invalid: ' + hookPath);
	    }

	    return function(req, res, next) {
	      if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
	        const token = req.headers.authorization.split(' ')[1];

	        try {
	          if (tools.validateHookToken(domain, webtaskUrl, hookPath, extensionSecret, token)) {
	            return next();
	          }
	        } catch (e) {
	          return next(e);
	        }
	      }

	      return next(new tools.HookTokenError('Hook token missing for the call to: ' + hookPath));
	    };
	  };
	};


/***/ },
/* 27 */
/***/ function(module, exports, __webpack_require__) {

	const tools = __webpack_require__(10);

	module.exports = function(config) {
	  return function(req, res, next) {
	    if (req.webtaskContext) {
	      config.setProvider(tools.configProvider.fromWebtaskContext(req.webtaskContext));
	    }

	    return next();
	  };
	};


/***/ },
/* 28 */
/***/ function(module, exports, __webpack_require__) {

	module.exports.dashboardAdmins = __webpack_require__(29);


/***/ },
/* 29 */
/***/ function(module, exports, __webpack_require__) {

	const express = __webpack_require__(5);
	const tools = __webpack_require__(10);

	const urlHelpers = __webpack_require__(11);

	module.exports = function(options) {
	  if (!options || typeof options !== 'object') {
	    throw new tools.ArgumentError('Must provide the options');
	  }

	  if (options.secret === null || options.secret === undefined) {
	    throw new tools.ArgumentError('Must provide a valid secret');
	  }

	  if (typeof options.secret !== 'string' || options.secret.length === 0) {
	    throw new tools.ArgumentError('The provided secret is invalid: ' + options.secret);
	  }

	  if (options.audience === null || options.audience === undefined) {
	    throw new tools.ArgumentError('Must provide a valid secret');
	  }

	  if (typeof options.audience !== 'string' || options.audience.length === 0) {
	    throw new tools.ArgumentError('The provided audience is invalid: ' + options.audience);
	  }

	  if (options.rta === null || options.rta === undefined) {
	    throw new tools.ArgumentError('Must provide a valid rta');
	  }

	  if (typeof options.rta !== 'string' || options.rta.length === 0) {
	    throw new tools.ArgumentError('The provided rta is invalid: ' + options.rta);
	  }

	  if (options.domain === null || options.domain === undefined) {
	    throw new tools.ArgumentError('Must provide a valid domain');
	  }

	  if (typeof options.domain !== 'string' || options.domain.length === 0) {
	    throw new tools.ArgumentError('The provided domain is invalid: ' + options.domain);
	  }

	  if (options.baseUrl === null || options.baseUrl === undefined) {
	    throw new tools.ArgumentError('Must provide a valid base URL');
	  }

	  if (typeof options.baseUrl !== 'string' || options.baseUrl.length === 0) {
	    throw new tools.ArgumentError('The provided base URL is invalid: ' + options.baseUrl);
	  }

	  if (options.clientName === null || options.clientName === undefined) {
	    throw new tools.ArgumentError('Must provide a valid client name');
	  }

	  if (typeof options.clientName !== 'string' || options.clientName.length === 0) {
	    throw new tools.ArgumentError('The provided client name is invalid: ' + options.clientName);
	  }

	  const sessionStorageKey = options.sessionStorageKey || 'apiToken';
	  const urlPrefix = options.urlPrefix || '';

	  const router = express.Router();
	  router.get(urlPrefix + '/login', function(req, res) {
	    const sessionManager = new tools.SessionManager(options.rta, options.domain, options.baseUrl);
	    res.redirect(sessionManager.createAuthorizeUrl({
	      redirectUri: urlHelpers.getBaseUrl(req) + urlPrefix + '/login/callback',
	      scopes: options.scopes,
	      expiration: options.expiration
	    }));
	  });

	  router.post(urlPrefix + '/login/callback', function(req, res, next) {
	    const sessionManager = new tools.SessionManager(options.rta, options.domain, options.baseUrl);
	    sessionManager.create(req.body.id_token, req.body.access_token, {
	      secret: options.secret,
	      issuer: options.baseUrl,
	      audience: options.audience
	    }).then(function(token) {
	      res.header('Content-Type', 'text/html');
	      res.status(200).send('<html>' +
	        '<head>' +
	          '<script type="text/javascript">' +
	            'sessionStorage.setItem("' + sessionStorageKey + '", "' + token + '");' +
	            'window.location.href = "' + urlHelpers.getBaseUrl(req) + '";' +
	          '</script>' +
	      '</html>');
	    })
	    .catch(function(err) {
	      next(err);
	    });
	  });

	  router.get(urlPrefix + '/logout', function(req, res) {
	    const encodedBaseUrl = encodeURIComponent(urlHelpers.getBaseUrl(req));
	    res.header('Content-Type', 'text/html');
	    res.status(200).send('<html>' +
	      '<head>' +
	        '<script type="text/javascript">' +
	          'sessionStorage.removeItem("' + sessionStorageKey + '");' +
	          'window.location.href = "https://"' + options.rta + '"/v2/logout/?returnTo=' + encodedBaseUrl + '&client_id=' + encodedBaseUrl + '";' +
	        '</script>' +
	    '</html>');
	  });

	  router.get('/.well-known/oauth2-client-configuration', function(req, res) {
	    res.header('Content-Type', 'application/json');
	    res.status(200).send({
	      redirect_uris: [ urlHelpers.getBaseUrl(req) + urlPrefix + '/login/callback' ],
	      client_name: options.clientName,
	      post_logout_redirect_uris: [ urlHelpers.getBaseUrl(req) ]
	    });
	  });

	  return router;
	};


/***/ },
/* 30 */
/***/ function(module, exports) {

	module.exports = {
		"title": "Auth0 Extension Boilerplate",
		"name": "auth0-extension-boilerplate",
		"version": "1.0.0",
		"author": "auth0",
		"description": "This is a Hello World extension",
		"type": "application",
		"repository": "https://github.com/auth0/auth0-extension-boilerplate",
		"keywords": [
			"auth0",
			"extension"
		]
	};

/***/ },
/* 31 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var _typeof2 = __webpack_require__(32);

	var _typeof3 = _interopRequireDefault(_typeof2);

	var _stringify = __webpack_require__(100);

	var _stringify2 = _interopRequireDefault(_stringify);

	function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

	var _ = __webpack_require__(102);
	var jwt = __webpack_require__(103);

	// https://gist.github.com/kurtsson/3f1c8efc0ccd549c9e31
	var formatXml = function formatXml(xml) {
	  var formatted = '';
	  var reg = /(>)(<)(\/*)/g;
	  xml = xml.toString().replace(reg, '$1\r\n$2$3');
	  var pad = 0;
	  var nodes = xml.split('\r\n');
	  for (var n in nodes) {
	    var node = nodes[n];
	    var indent = 0;
	    if (node.match(/.+<\/\w[^>]*>$/)) {
	      indent = 0;
	    } else if (node.match(/^<\/\w/)) {
	      if (pad !== 0) {
	        pad -= 1;
	      }
	    } else if (node.match(/^<\w[^>]*[^\/]>.*$/)) {
	      indent = 1;
	    } else {
	      indent = 0;
	    }

	    var padding = '';
	    for (var i = 0; i < pad; i++) {
	      padding += '  ';
	    }

	    formatted += padding + node + '\r\n';
	    pad += indent;
	  }

	  return formatted.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/ /g, '&nbsp;');
	};

	var highlight = function highlight(json) {
	  if (typeof json != 'string') {
	    json = (0, _stringify2.default)(json, undefined, 2);
	  }
	  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
	  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
	    var cls = 'json-value';
	    if (/^"/.test(match)) {
	      if (/:$/.test(match)) {
	        cls = 'json-key';
	      } else {
	        cls = 'json-string';
	      }
	    } else if (/true|false/.test(match)) {
	      cls = 'json-value';
	    }
	    return '<span class="' + cls + '">' + match + '</span>';
	  });
	};

	module.exports.wsFedResult = function (response) {
	  if (!response || !response.length) {
	    return null;
	  }

	  try {
	    return formatXml(response);
	  } catch (e) {
	    return response;
	  }
	};

	module.exports.samlResponse = function (response) {
	  if (!response || !response.length) {
	    return null;
	  }

	  try {
	    var xml = new Buffer(response, 'base64').toString();
	    return formatXml(xml);
	  } catch (e) {
	    return response;
	  }
	};

	module.exports.jwt = function (token) {
	  if (!token || token.indexOf('ey') !== 0) {
	    return null;
	  }

	  try {
	    var decoded = jwt.decode(token, { complete: true });
	    return highlight(decoded);
	  } catch (e) {
	    return token;
	  }
	};

	module.exports.base64url = function (b) {
	  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	};

	module.exports.syntaxHighlight = function (obj) {
	  try {
	    var _ret = function () {
	      var keys = _.keys(obj);
	      if (!keys.length) {
	        return {
	          v: null
	        };
	      }

	      var orderedObject = {};
	      keys.sort().forEach(function (key) {
	        orderedObject[key] = obj[key];
	      });

	      return {
	        v: highlight(orderedObject)
	      };
	    }();

	    if ((typeof _ret === 'undefined' ? 'undefined' : (0, _typeof3.default)(_ret)) === "object") return _ret.v;
	  } catch (e) {
	    return (0, _stringify2.default)(obj, null, 2);
	  }
	};

/***/ },
/* 32 */
/***/ function(module, exports, __webpack_require__) {

	"use strict";

	exports.__esModule = true;

	var _iterator = __webpack_require__(33);

	var _iterator2 = _interopRequireDefault(_iterator);

	var _symbol = __webpack_require__(84);

	var _symbol2 = _interopRequireDefault(_symbol);

	var _typeof = typeof _symbol2.default === "function" && typeof _iterator2.default === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof _symbol2.default === "function" && obj.constructor === _symbol2.default && obj !== _symbol2.default.prototype ? "symbol" : typeof obj; };

	function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

	exports.default = typeof _symbol2.default === "function" && _typeof(_iterator2.default) === "symbol" ? function (obj) {
	  return typeof obj === "undefined" ? "undefined" : _typeof(obj);
	} : function (obj) {
	  return obj && typeof _symbol2.default === "function" && obj.constructor === _symbol2.default && obj !== _symbol2.default.prototype ? "symbol" : typeof obj === "undefined" ? "undefined" : _typeof(obj);
	};

/***/ },
/* 33 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = { "default": __webpack_require__(34), __esModule: true };

/***/ },
/* 34 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(35);
	__webpack_require__(79);
	module.exports = __webpack_require__(83).f('iterator');

/***/ },
/* 35 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	var $at  = __webpack_require__(36)(true);

	// 21.1.3.27 String.prototype[@@iterator]()
	__webpack_require__(39)(String, 'String', function(iterated){
	  this._t = String(iterated); // target
	  this._i = 0;                // next index
	// 21.1.5.2.1 %StringIteratorPrototype%.next()
	}, function(){
	  var O     = this._t
	    , index = this._i
	    , point;
	  if(index >= O.length)return {value: undefined, done: true};
	  point = $at(O, index);
	  this._i += point.length;
	  return {value: point, done: false};
	});

/***/ },
/* 36 */
/***/ function(module, exports, __webpack_require__) {

	var toInteger = __webpack_require__(37)
	  , defined   = __webpack_require__(38);
	// true  -> String#at
	// false -> String#codePointAt
	module.exports = function(TO_STRING){
	  return function(that, pos){
	    var s = String(defined(that))
	      , i = toInteger(pos)
	      , l = s.length
	      , a, b;
	    if(i < 0 || i >= l)return TO_STRING ? '' : undefined;
	    a = s.charCodeAt(i);
	    return a < 0xd800 || a > 0xdbff || i + 1 === l || (b = s.charCodeAt(i + 1)) < 0xdc00 || b > 0xdfff
	      ? TO_STRING ? s.charAt(i) : a
	      : TO_STRING ? s.slice(i, i + 2) : (a - 0xd800 << 10) + (b - 0xdc00) + 0x10000;
	  };
	};

/***/ },
/* 37 */
/***/ function(module, exports) {

	// 7.1.4 ToInteger
	var ceil  = Math.ceil
	  , floor = Math.floor;
	module.exports = function(it){
	  return isNaN(it = +it) ? 0 : (it > 0 ? floor : ceil)(it);
	};

/***/ },
/* 38 */
/***/ function(module, exports) {

	// 7.2.1 RequireObjectCoercible(argument)
	module.exports = function(it){
	  if(it == undefined)throw TypeError("Can't call method on  " + it);
	  return it;
	};

/***/ },
/* 39 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	var LIBRARY        = __webpack_require__(40)
	  , $export        = __webpack_require__(41)
	  , redefine       = __webpack_require__(56)
	  , hide           = __webpack_require__(46)
	  , has            = __webpack_require__(57)
	  , Iterators      = __webpack_require__(58)
	  , $iterCreate    = __webpack_require__(59)
	  , setToStringTag = __webpack_require__(75)
	  , getPrototypeOf = __webpack_require__(77)
	  , ITERATOR       = __webpack_require__(76)('iterator')
	  , BUGGY          = !([].keys && 'next' in [].keys()) // Safari has buggy iterators w/o `next`
	  , FF_ITERATOR    = '@@iterator'
	  , KEYS           = 'keys'
	  , VALUES         = 'values';

	var returnThis = function(){ return this; };

	module.exports = function(Base, NAME, Constructor, next, DEFAULT, IS_SET, FORCED){
	  $iterCreate(Constructor, NAME, next);
	  var getMethod = function(kind){
	    if(!BUGGY && kind in proto)return proto[kind];
	    switch(kind){
	      case KEYS: return function keys(){ return new Constructor(this, kind); };
	      case VALUES: return function values(){ return new Constructor(this, kind); };
	    } return function entries(){ return new Constructor(this, kind); };
	  };
	  var TAG        = NAME + ' Iterator'
	    , DEF_VALUES = DEFAULT == VALUES
	    , VALUES_BUG = false
	    , proto      = Base.prototype
	    , $native    = proto[ITERATOR] || proto[FF_ITERATOR] || DEFAULT && proto[DEFAULT]
	    , $default   = $native || getMethod(DEFAULT)
	    , $entries   = DEFAULT ? !DEF_VALUES ? $default : getMethod('entries') : undefined
	    , $anyNative = NAME == 'Array' ? proto.entries || $native : $native
	    , methods, key, IteratorPrototype;
	  // Fix native
	  if($anyNative){
	    IteratorPrototype = getPrototypeOf($anyNative.call(new Base));
	    if(IteratorPrototype !== Object.prototype){
	      // Set @@toStringTag to native iterators
	      setToStringTag(IteratorPrototype, TAG, true);
	      // fix for some old engines
	      if(!LIBRARY && !has(IteratorPrototype, ITERATOR))hide(IteratorPrototype, ITERATOR, returnThis);
	    }
	  }
	  // fix Array#{values, @@iterator}.name in V8 / FF
	  if(DEF_VALUES && $native && $native.name !== VALUES){
	    VALUES_BUG = true;
	    $default = function values(){ return $native.call(this); };
	  }
	  // Define iterator
	  if((!LIBRARY || FORCED) && (BUGGY || VALUES_BUG || !proto[ITERATOR])){
	    hide(proto, ITERATOR, $default);
	  }
	  // Plug for library
	  Iterators[NAME] = $default;
	  Iterators[TAG]  = returnThis;
	  if(DEFAULT){
	    methods = {
	      values:  DEF_VALUES ? $default : getMethod(VALUES),
	      keys:    IS_SET     ? $default : getMethod(KEYS),
	      entries: $entries
	    };
	    if(FORCED)for(key in methods){
	      if(!(key in proto))redefine(proto, key, methods[key]);
	    } else $export($export.P + $export.F * (BUGGY || VALUES_BUG), NAME, methods);
	  }
	  return methods;
	};

/***/ },
/* 40 */
/***/ function(module, exports) {

	module.exports = true;

/***/ },
/* 41 */
/***/ function(module, exports, __webpack_require__) {

	var global    = __webpack_require__(42)
	  , core      = __webpack_require__(43)
	  , ctx       = __webpack_require__(44)
	  , hide      = __webpack_require__(46)
	  , PROTOTYPE = 'prototype';

	var $export = function(type, name, source){
	  var IS_FORCED = type & $export.F
	    , IS_GLOBAL = type & $export.G
	    , IS_STATIC = type & $export.S
	    , IS_PROTO  = type & $export.P
	    , IS_BIND   = type & $export.B
	    , IS_WRAP   = type & $export.W
	    , exports   = IS_GLOBAL ? core : core[name] || (core[name] = {})
	    , expProto  = exports[PROTOTYPE]
	    , target    = IS_GLOBAL ? global : IS_STATIC ? global[name] : (global[name] || {})[PROTOTYPE]
	    , key, own, out;
	  if(IS_GLOBAL)source = name;
	  for(key in source){
	    // contains in native
	    own = !IS_FORCED && target && target[key] !== undefined;
	    if(own && key in exports)continue;
	    // export native or passed
	    out = own ? target[key] : source[key];
	    // prevent global pollution for namespaces
	    exports[key] = IS_GLOBAL && typeof target[key] != 'function' ? source[key]
	    // bind timers to global for call from export context
	    : IS_BIND && own ? ctx(out, global)
	    // wrap global constructors for prevent change them in library
	    : IS_WRAP && target[key] == out ? (function(C){
	      var F = function(a, b, c){
	        if(this instanceof C){
	          switch(arguments.length){
	            case 0: return new C;
	            case 1: return new C(a);
	            case 2: return new C(a, b);
	          } return new C(a, b, c);
	        } return C.apply(this, arguments);
	      };
	      F[PROTOTYPE] = C[PROTOTYPE];
	      return F;
	    // make static versions for prototype methods
	    })(out) : IS_PROTO && typeof out == 'function' ? ctx(Function.call, out) : out;
	    // export proto methods to core.%CONSTRUCTOR%.methods.%NAME%
	    if(IS_PROTO){
	      (exports.virtual || (exports.virtual = {}))[key] = out;
	      // export proto methods to core.%CONSTRUCTOR%.prototype.%NAME%
	      if(type & $export.R && expProto && !expProto[key])hide(expProto, key, out);
	    }
	  }
	};
	// type bitmap
	$export.F = 1;   // forced
	$export.G = 2;   // global
	$export.S = 4;   // static
	$export.P = 8;   // proto
	$export.B = 16;  // bind
	$export.W = 32;  // wrap
	$export.U = 64;  // safe
	$export.R = 128; // real proto method for `library` 
	module.exports = $export;

/***/ },
/* 42 */
/***/ function(module, exports) {

	// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
	var global = module.exports = typeof window != 'undefined' && window.Math == Math
	  ? window : typeof self != 'undefined' && self.Math == Math ? self : Function('return this')();
	if(typeof __g == 'number')__g = global; // eslint-disable-line no-undef

/***/ },
/* 43 */
/***/ function(module, exports) {

	var core = module.exports = {version: '2.4.0'};
	if(typeof __e == 'number')__e = core; // eslint-disable-line no-undef

/***/ },
/* 44 */
/***/ function(module, exports, __webpack_require__) {

	// optional / simple context binding
	var aFunction = __webpack_require__(45);
	module.exports = function(fn, that, length){
	  aFunction(fn);
	  if(that === undefined)return fn;
	  switch(length){
	    case 1: return function(a){
	      return fn.call(that, a);
	    };
	    case 2: return function(a, b){
	      return fn.call(that, a, b);
	    };
	    case 3: return function(a, b, c){
	      return fn.call(that, a, b, c);
	    };
	  }
	  return function(/* ...args */){
	    return fn.apply(that, arguments);
	  };
	};

/***/ },
/* 45 */
/***/ function(module, exports) {

	module.exports = function(it){
	  if(typeof it != 'function')throw TypeError(it + ' is not a function!');
	  return it;
	};

/***/ },
/* 46 */
/***/ function(module, exports, __webpack_require__) {

	var dP         = __webpack_require__(47)
	  , createDesc = __webpack_require__(55);
	module.exports = __webpack_require__(51) ? function(object, key, value){
	  return dP.f(object, key, createDesc(1, value));
	} : function(object, key, value){
	  object[key] = value;
	  return object;
	};

/***/ },
/* 47 */
/***/ function(module, exports, __webpack_require__) {

	var anObject       = __webpack_require__(48)
	  , IE8_DOM_DEFINE = __webpack_require__(50)
	  , toPrimitive    = __webpack_require__(54)
	  , dP             = Object.defineProperty;

	exports.f = __webpack_require__(51) ? Object.defineProperty : function defineProperty(O, P, Attributes){
	  anObject(O);
	  P = toPrimitive(P, true);
	  anObject(Attributes);
	  if(IE8_DOM_DEFINE)try {
	    return dP(O, P, Attributes);
	  } catch(e){ /* empty */ }
	  if('get' in Attributes || 'set' in Attributes)throw TypeError('Accessors not supported!');
	  if('value' in Attributes)O[P] = Attributes.value;
	  return O;
	};

/***/ },
/* 48 */
/***/ function(module, exports, __webpack_require__) {

	var isObject = __webpack_require__(49);
	module.exports = function(it){
	  if(!isObject(it))throw TypeError(it + ' is not an object!');
	  return it;
	};

/***/ },
/* 49 */
/***/ function(module, exports) {

	module.exports = function(it){
	  return typeof it === 'object' ? it !== null : typeof it === 'function';
	};

/***/ },
/* 50 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = !__webpack_require__(51) && !__webpack_require__(52)(function(){
	  return Object.defineProperty(__webpack_require__(53)('div'), 'a', {get: function(){ return 7; }}).a != 7;
	});

/***/ },
/* 51 */
/***/ function(module, exports, __webpack_require__) {

	// Thank's IE8 for his funny defineProperty
	module.exports = !__webpack_require__(52)(function(){
	  return Object.defineProperty({}, 'a', {get: function(){ return 7; }}).a != 7;
	});

/***/ },
/* 52 */
/***/ function(module, exports) {

	module.exports = function(exec){
	  try {
	    return !!exec();
	  } catch(e){
	    return true;
	  }
	};

/***/ },
/* 53 */
/***/ function(module, exports, __webpack_require__) {

	var isObject = __webpack_require__(49)
	  , document = __webpack_require__(42).document
	  // in old IE typeof document.createElement is 'object'
	  , is = isObject(document) && isObject(document.createElement);
	module.exports = function(it){
	  return is ? document.createElement(it) : {};
	};

/***/ },
/* 54 */
/***/ function(module, exports, __webpack_require__) {

	// 7.1.1 ToPrimitive(input [, PreferredType])
	var isObject = __webpack_require__(49);
	// instead of the ES6 spec version, we didn't implement @@toPrimitive case
	// and the second argument - flag - preferred type is a string
	module.exports = function(it, S){
	  if(!isObject(it))return it;
	  var fn, val;
	  if(S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it)))return val;
	  if(typeof (fn = it.valueOf) == 'function' && !isObject(val = fn.call(it)))return val;
	  if(!S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it)))return val;
	  throw TypeError("Can't convert object to primitive value");
	};

/***/ },
/* 55 */
/***/ function(module, exports) {

	module.exports = function(bitmap, value){
	  return {
	    enumerable  : !(bitmap & 1),
	    configurable: !(bitmap & 2),
	    writable    : !(bitmap & 4),
	    value       : value
	  };
	};

/***/ },
/* 56 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = __webpack_require__(46);

/***/ },
/* 57 */
/***/ function(module, exports) {

	var hasOwnProperty = {}.hasOwnProperty;
	module.exports = function(it, key){
	  return hasOwnProperty.call(it, key);
	};

/***/ },
/* 58 */
/***/ function(module, exports) {

	module.exports = {};

/***/ },
/* 59 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	var create         = __webpack_require__(60)
	  , descriptor     = __webpack_require__(55)
	  , setToStringTag = __webpack_require__(75)
	  , IteratorPrototype = {};

	// 25.1.2.1.1 %IteratorPrototype%[@@iterator]()
	__webpack_require__(46)(IteratorPrototype, __webpack_require__(76)('iterator'), function(){ return this; });

	module.exports = function(Constructor, NAME, next){
	  Constructor.prototype = create(IteratorPrototype, {next: descriptor(1, next)});
	  setToStringTag(Constructor, NAME + ' Iterator');
	};

/***/ },
/* 60 */
/***/ function(module, exports, __webpack_require__) {

	// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
	var anObject    = __webpack_require__(48)
	  , dPs         = __webpack_require__(61)
	  , enumBugKeys = __webpack_require__(73)
	  , IE_PROTO    = __webpack_require__(70)('IE_PROTO')
	  , Empty       = function(){ /* empty */ }
	  , PROTOTYPE   = 'prototype';

	// Create object with fake `null` prototype: use iframe Object with cleared prototype
	var createDict = function(){
	  // Thrash, waste and sodomy: IE GC bug
	  var iframe = __webpack_require__(53)('iframe')
	    , i      = enumBugKeys.length
	    , lt     = '<'
	    , gt     = '>'
	    , iframeDocument;
	  iframe.style.display = 'none';
	  __webpack_require__(74).appendChild(iframe);
	  iframe.src = 'javascript:'; // eslint-disable-line no-script-url
	  // createDict = iframe.contentWindow.Object;
	  // html.removeChild(iframe);
	  iframeDocument = iframe.contentWindow.document;
	  iframeDocument.open();
	  iframeDocument.write(lt + 'script' + gt + 'document.F=Object' + lt + '/script' + gt);
	  iframeDocument.close();
	  createDict = iframeDocument.F;
	  while(i--)delete createDict[PROTOTYPE][enumBugKeys[i]];
	  return createDict();
	};

	module.exports = Object.create || function create(O, Properties){
	  var result;
	  if(O !== null){
	    Empty[PROTOTYPE] = anObject(O);
	    result = new Empty;
	    Empty[PROTOTYPE] = null;
	    // add "__proto__" for Object.getPrototypeOf polyfill
	    result[IE_PROTO] = O;
	  } else result = createDict();
	  return Properties === undefined ? result : dPs(result, Properties);
	};


/***/ },
/* 61 */
/***/ function(module, exports, __webpack_require__) {

	var dP       = __webpack_require__(47)
	  , anObject = __webpack_require__(48)
	  , getKeys  = __webpack_require__(62);

	module.exports = __webpack_require__(51) ? Object.defineProperties : function defineProperties(O, Properties){
	  anObject(O);
	  var keys   = getKeys(Properties)
	    , length = keys.length
	    , i = 0
	    , P;
	  while(length > i)dP.f(O, P = keys[i++], Properties[P]);
	  return O;
	};

/***/ },
/* 62 */
/***/ function(module, exports, __webpack_require__) {

	// 19.1.2.14 / 15.2.3.14 Object.keys(O)
	var $keys       = __webpack_require__(63)
	  , enumBugKeys = __webpack_require__(73);

	module.exports = Object.keys || function keys(O){
	  return $keys(O, enumBugKeys);
	};

/***/ },
/* 63 */
/***/ function(module, exports, __webpack_require__) {

	var has          = __webpack_require__(57)
	  , toIObject    = __webpack_require__(64)
	  , arrayIndexOf = __webpack_require__(67)(false)
	  , IE_PROTO     = __webpack_require__(70)('IE_PROTO');

	module.exports = function(object, names){
	  var O      = toIObject(object)
	    , i      = 0
	    , result = []
	    , key;
	  for(key in O)if(key != IE_PROTO)has(O, key) && result.push(key);
	  // Don't enum bug & hidden keys
	  while(names.length > i)if(has(O, key = names[i++])){
	    ~arrayIndexOf(result, key) || result.push(key);
	  }
	  return result;
	};

/***/ },
/* 64 */
/***/ function(module, exports, __webpack_require__) {

	// to indexed object, toObject with fallback for non-array-like ES3 strings
	var IObject = __webpack_require__(65)
	  , defined = __webpack_require__(38);
	module.exports = function(it){
	  return IObject(defined(it));
	};

/***/ },
/* 65 */
/***/ function(module, exports, __webpack_require__) {

	// fallback for non-array-like ES3 and non-enumerable old V8 strings
	var cof = __webpack_require__(66);
	module.exports = Object('z').propertyIsEnumerable(0) ? Object : function(it){
	  return cof(it) == 'String' ? it.split('') : Object(it);
	};

/***/ },
/* 66 */
/***/ function(module, exports) {

	var toString = {}.toString;

	module.exports = function(it){
	  return toString.call(it).slice(8, -1);
	};

/***/ },
/* 67 */
/***/ function(module, exports, __webpack_require__) {

	// false -> Array#indexOf
	// true  -> Array#includes
	var toIObject = __webpack_require__(64)
	  , toLength  = __webpack_require__(68)
	  , toIndex   = __webpack_require__(69);
	module.exports = function(IS_INCLUDES){
	  return function($this, el, fromIndex){
	    var O      = toIObject($this)
	      , length = toLength(O.length)
	      , index  = toIndex(fromIndex, length)
	      , value;
	    // Array#includes uses SameValueZero equality algorithm
	    if(IS_INCLUDES && el != el)while(length > index){
	      value = O[index++];
	      if(value != value)return true;
	    // Array#toIndex ignores holes, Array#includes - not
	    } else for(;length > index; index++)if(IS_INCLUDES || index in O){
	      if(O[index] === el)return IS_INCLUDES || index || 0;
	    } return !IS_INCLUDES && -1;
	  };
	};

/***/ },
/* 68 */
/***/ function(module, exports, __webpack_require__) {

	// 7.1.15 ToLength
	var toInteger = __webpack_require__(37)
	  , min       = Math.min;
	module.exports = function(it){
	  return it > 0 ? min(toInteger(it), 0x1fffffffffffff) : 0; // pow(2, 53) - 1 == 9007199254740991
	};

/***/ },
/* 69 */
/***/ function(module, exports, __webpack_require__) {

	var toInteger = __webpack_require__(37)
	  , max       = Math.max
	  , min       = Math.min;
	module.exports = function(index, length){
	  index = toInteger(index);
	  return index < 0 ? max(index + length, 0) : min(index, length);
	};

/***/ },
/* 70 */
/***/ function(module, exports, __webpack_require__) {

	var shared = __webpack_require__(71)('keys')
	  , uid    = __webpack_require__(72);
	module.exports = function(key){
	  return shared[key] || (shared[key] = uid(key));
	};

/***/ },
/* 71 */
/***/ function(module, exports, __webpack_require__) {

	var global = __webpack_require__(42)
	  , SHARED = '__core-js_shared__'
	  , store  = global[SHARED] || (global[SHARED] = {});
	module.exports = function(key){
	  return store[key] || (store[key] = {});
	};

/***/ },
/* 72 */
/***/ function(module, exports) {

	var id = 0
	  , px = Math.random();
	module.exports = function(key){
	  return 'Symbol('.concat(key === undefined ? '' : key, ')_', (++id + px).toString(36));
	};

/***/ },
/* 73 */
/***/ function(module, exports) {

	// IE 8- don't enum bug keys
	module.exports = (
	  'constructor,hasOwnProperty,isPrototypeOf,propertyIsEnumerable,toLocaleString,toString,valueOf'
	).split(',');

/***/ },
/* 74 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = __webpack_require__(42).document && document.documentElement;

/***/ },
/* 75 */
/***/ function(module, exports, __webpack_require__) {

	var def = __webpack_require__(47).f
	  , has = __webpack_require__(57)
	  , TAG = __webpack_require__(76)('toStringTag');

	module.exports = function(it, tag, stat){
	  if(it && !has(it = stat ? it : it.prototype, TAG))def(it, TAG, {configurable: true, value: tag});
	};

/***/ },
/* 76 */
/***/ function(module, exports, __webpack_require__) {

	var store      = __webpack_require__(71)('wks')
	  , uid        = __webpack_require__(72)
	  , Symbol     = __webpack_require__(42).Symbol
	  , USE_SYMBOL = typeof Symbol == 'function';

	var $exports = module.exports = function(name){
	  return store[name] || (store[name] =
	    USE_SYMBOL && Symbol[name] || (USE_SYMBOL ? Symbol : uid)('Symbol.' + name));
	};

	$exports.store = store;

/***/ },
/* 77 */
/***/ function(module, exports, __webpack_require__) {

	// 19.1.2.9 / 15.2.3.2 Object.getPrototypeOf(O)
	var has         = __webpack_require__(57)
	  , toObject    = __webpack_require__(78)
	  , IE_PROTO    = __webpack_require__(70)('IE_PROTO')
	  , ObjectProto = Object.prototype;

	module.exports = Object.getPrototypeOf || function(O){
	  O = toObject(O);
	  if(has(O, IE_PROTO))return O[IE_PROTO];
	  if(typeof O.constructor == 'function' && O instanceof O.constructor){
	    return O.constructor.prototype;
	  } return O instanceof Object ? ObjectProto : null;
	};

/***/ },
/* 78 */
/***/ function(module, exports, __webpack_require__) {

	// 7.1.13 ToObject(argument)
	var defined = __webpack_require__(38);
	module.exports = function(it){
	  return Object(defined(it));
	};

/***/ },
/* 79 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(80);
	var global        = __webpack_require__(42)
	  , hide          = __webpack_require__(46)
	  , Iterators     = __webpack_require__(58)
	  , TO_STRING_TAG = __webpack_require__(76)('toStringTag');

	for(var collections = ['NodeList', 'DOMTokenList', 'MediaList', 'StyleSheetList', 'CSSRuleList'], i = 0; i < 5; i++){
	  var NAME       = collections[i]
	    , Collection = global[NAME]
	    , proto      = Collection && Collection.prototype;
	  if(proto && !proto[TO_STRING_TAG])hide(proto, TO_STRING_TAG, NAME);
	  Iterators[NAME] = Iterators.Array;
	}

/***/ },
/* 80 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	var addToUnscopables = __webpack_require__(81)
	  , step             = __webpack_require__(82)
	  , Iterators        = __webpack_require__(58)
	  , toIObject        = __webpack_require__(64);

	// 22.1.3.4 Array.prototype.entries()
	// 22.1.3.13 Array.prototype.keys()
	// 22.1.3.29 Array.prototype.values()
	// 22.1.3.30 Array.prototype[@@iterator]()
	module.exports = __webpack_require__(39)(Array, 'Array', function(iterated, kind){
	  this._t = toIObject(iterated); // target
	  this._i = 0;                   // next index
	  this._k = kind;                // kind
	// 22.1.5.2.1 %ArrayIteratorPrototype%.next()
	}, function(){
	  var O     = this._t
	    , kind  = this._k
	    , index = this._i++;
	  if(!O || index >= O.length){
	    this._t = undefined;
	    return step(1);
	  }
	  if(kind == 'keys'  )return step(0, index);
	  if(kind == 'values')return step(0, O[index]);
	  return step(0, [index, O[index]]);
	}, 'values');

	// argumentsList[@@iterator] is %ArrayProto_values% (9.4.4.6, 9.4.4.7)
	Iterators.Arguments = Iterators.Array;

	addToUnscopables('keys');
	addToUnscopables('values');
	addToUnscopables('entries');

/***/ },
/* 81 */
/***/ function(module, exports) {

	module.exports = function(){ /* empty */ };

/***/ },
/* 82 */
/***/ function(module, exports) {

	module.exports = function(done, value){
	  return {value: value, done: !!done};
	};

/***/ },
/* 83 */
/***/ function(module, exports, __webpack_require__) {

	exports.f = __webpack_require__(76);

/***/ },
/* 84 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = { "default": __webpack_require__(85), __esModule: true };

/***/ },
/* 85 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(86);
	__webpack_require__(97);
	__webpack_require__(98);
	__webpack_require__(99);
	module.exports = __webpack_require__(43).Symbol;

/***/ },
/* 86 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	// ECMAScript 6 symbols shim
	var global         = __webpack_require__(42)
	  , has            = __webpack_require__(57)
	  , DESCRIPTORS    = __webpack_require__(51)
	  , $export        = __webpack_require__(41)
	  , redefine       = __webpack_require__(56)
	  , META           = __webpack_require__(87).KEY
	  , $fails         = __webpack_require__(52)
	  , shared         = __webpack_require__(71)
	  , setToStringTag = __webpack_require__(75)
	  , uid            = __webpack_require__(72)
	  , wks            = __webpack_require__(76)
	  , wksExt         = __webpack_require__(83)
	  , wksDefine      = __webpack_require__(88)
	  , keyOf          = __webpack_require__(89)
	  , enumKeys       = __webpack_require__(90)
	  , isArray        = __webpack_require__(93)
	  , anObject       = __webpack_require__(48)
	  , toIObject      = __webpack_require__(64)
	  , toPrimitive    = __webpack_require__(54)
	  , createDesc     = __webpack_require__(55)
	  , _create        = __webpack_require__(60)
	  , gOPNExt        = __webpack_require__(94)
	  , $GOPD          = __webpack_require__(96)
	  , $DP            = __webpack_require__(47)
	  , $keys          = __webpack_require__(62)
	  , gOPD           = $GOPD.f
	  , dP             = $DP.f
	  , gOPN           = gOPNExt.f
	  , $Symbol        = global.Symbol
	  , $JSON          = global.JSON
	  , _stringify     = $JSON && $JSON.stringify
	  , PROTOTYPE      = 'prototype'
	  , HIDDEN         = wks('_hidden')
	  , TO_PRIMITIVE   = wks('toPrimitive')
	  , isEnum         = {}.propertyIsEnumerable
	  , SymbolRegistry = shared('symbol-registry')
	  , AllSymbols     = shared('symbols')
	  , OPSymbols      = shared('op-symbols')
	  , ObjectProto    = Object[PROTOTYPE]
	  , USE_NATIVE     = typeof $Symbol == 'function'
	  , QObject        = global.QObject;
	// Don't use setters in Qt Script, https://github.com/zloirock/core-js/issues/173
	var setter = !QObject || !QObject[PROTOTYPE] || !QObject[PROTOTYPE].findChild;

	// fallback for old Android, https://code.google.com/p/v8/issues/detail?id=687
	var setSymbolDesc = DESCRIPTORS && $fails(function(){
	  return _create(dP({}, 'a', {
	    get: function(){ return dP(this, 'a', {value: 7}).a; }
	  })).a != 7;
	}) ? function(it, key, D){
	  var protoDesc = gOPD(ObjectProto, key);
	  if(protoDesc)delete ObjectProto[key];
	  dP(it, key, D);
	  if(protoDesc && it !== ObjectProto)dP(ObjectProto, key, protoDesc);
	} : dP;

	var wrap = function(tag){
	  var sym = AllSymbols[tag] = _create($Symbol[PROTOTYPE]);
	  sym._k = tag;
	  return sym;
	};

	var isSymbol = USE_NATIVE && typeof $Symbol.iterator == 'symbol' ? function(it){
	  return typeof it == 'symbol';
	} : function(it){
	  return it instanceof $Symbol;
	};

	var $defineProperty = function defineProperty(it, key, D){
	  if(it === ObjectProto)$defineProperty(OPSymbols, key, D);
	  anObject(it);
	  key = toPrimitive(key, true);
	  anObject(D);
	  if(has(AllSymbols, key)){
	    if(!D.enumerable){
	      if(!has(it, HIDDEN))dP(it, HIDDEN, createDesc(1, {}));
	      it[HIDDEN][key] = true;
	    } else {
	      if(has(it, HIDDEN) && it[HIDDEN][key])it[HIDDEN][key] = false;
	      D = _create(D, {enumerable: createDesc(0, false)});
	    } return setSymbolDesc(it, key, D);
	  } return dP(it, key, D);
	};
	var $defineProperties = function defineProperties(it, P){
	  anObject(it);
	  var keys = enumKeys(P = toIObject(P))
	    , i    = 0
	    , l = keys.length
	    , key;
	  while(l > i)$defineProperty(it, key = keys[i++], P[key]);
	  return it;
	};
	var $create = function create(it, P){
	  return P === undefined ? _create(it) : $defineProperties(_create(it), P);
	};
	var $propertyIsEnumerable = function propertyIsEnumerable(key){
	  var E = isEnum.call(this, key = toPrimitive(key, true));
	  if(this === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key))return false;
	  return E || !has(this, key) || !has(AllSymbols, key) || has(this, HIDDEN) && this[HIDDEN][key] ? E : true;
	};
	var $getOwnPropertyDescriptor = function getOwnPropertyDescriptor(it, key){
	  it  = toIObject(it);
	  key = toPrimitive(key, true);
	  if(it === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key))return;
	  var D = gOPD(it, key);
	  if(D && has(AllSymbols, key) && !(has(it, HIDDEN) && it[HIDDEN][key]))D.enumerable = true;
	  return D;
	};
	var $getOwnPropertyNames = function getOwnPropertyNames(it){
	  var names  = gOPN(toIObject(it))
	    , result = []
	    , i      = 0
	    , key;
	  while(names.length > i){
	    if(!has(AllSymbols, key = names[i++]) && key != HIDDEN && key != META)result.push(key);
	  } return result;
	};
	var $getOwnPropertySymbols = function getOwnPropertySymbols(it){
	  var IS_OP  = it === ObjectProto
	    , names  = gOPN(IS_OP ? OPSymbols : toIObject(it))
	    , result = []
	    , i      = 0
	    , key;
	  while(names.length > i){
	    if(has(AllSymbols, key = names[i++]) && (IS_OP ? has(ObjectProto, key) : true))result.push(AllSymbols[key]);
	  } return result;
	};

	// 19.4.1.1 Symbol([description])
	if(!USE_NATIVE){
	  $Symbol = function Symbol(){
	    if(this instanceof $Symbol)throw TypeError('Symbol is not a constructor!');
	    var tag = uid(arguments.length > 0 ? arguments[0] : undefined);
	    var $set = function(value){
	      if(this === ObjectProto)$set.call(OPSymbols, value);
	      if(has(this, HIDDEN) && has(this[HIDDEN], tag))this[HIDDEN][tag] = false;
	      setSymbolDesc(this, tag, createDesc(1, value));
	    };
	    if(DESCRIPTORS && setter)setSymbolDesc(ObjectProto, tag, {configurable: true, set: $set});
	    return wrap(tag);
	  };
	  redefine($Symbol[PROTOTYPE], 'toString', function toString(){
	    return this._k;
	  });

	  $GOPD.f = $getOwnPropertyDescriptor;
	  $DP.f   = $defineProperty;
	  __webpack_require__(95).f = gOPNExt.f = $getOwnPropertyNames;
	  __webpack_require__(92).f  = $propertyIsEnumerable;
	  __webpack_require__(91).f = $getOwnPropertySymbols;

	  if(DESCRIPTORS && !__webpack_require__(40)){
	    redefine(ObjectProto, 'propertyIsEnumerable', $propertyIsEnumerable, true);
	  }

	  wksExt.f = function(name){
	    return wrap(wks(name));
	  }
	}

	$export($export.G + $export.W + $export.F * !USE_NATIVE, {Symbol: $Symbol});

	for(var symbols = (
	  // 19.4.2.2, 19.4.2.3, 19.4.2.4, 19.4.2.6, 19.4.2.8, 19.4.2.9, 19.4.2.10, 19.4.2.11, 19.4.2.12, 19.4.2.13, 19.4.2.14
	  'hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables'
	).split(','), i = 0; symbols.length > i; )wks(symbols[i++]);

	for(var symbols = $keys(wks.store), i = 0; symbols.length > i; )wksDefine(symbols[i++]);

	$export($export.S + $export.F * !USE_NATIVE, 'Symbol', {
	  // 19.4.2.1 Symbol.for(key)
	  'for': function(key){
	    return has(SymbolRegistry, key += '')
	      ? SymbolRegistry[key]
	      : SymbolRegistry[key] = $Symbol(key);
	  },
	  // 19.4.2.5 Symbol.keyFor(sym)
	  keyFor: function keyFor(key){
	    if(isSymbol(key))return keyOf(SymbolRegistry, key);
	    throw TypeError(key + ' is not a symbol!');
	  },
	  useSetter: function(){ setter = true; },
	  useSimple: function(){ setter = false; }
	});

	$export($export.S + $export.F * !USE_NATIVE, 'Object', {
	  // 19.1.2.2 Object.create(O [, Properties])
	  create: $create,
	  // 19.1.2.4 Object.defineProperty(O, P, Attributes)
	  defineProperty: $defineProperty,
	  // 19.1.2.3 Object.defineProperties(O, Properties)
	  defineProperties: $defineProperties,
	  // 19.1.2.6 Object.getOwnPropertyDescriptor(O, P)
	  getOwnPropertyDescriptor: $getOwnPropertyDescriptor,
	  // 19.1.2.7 Object.getOwnPropertyNames(O)
	  getOwnPropertyNames: $getOwnPropertyNames,
	  // 19.1.2.8 Object.getOwnPropertySymbols(O)
	  getOwnPropertySymbols: $getOwnPropertySymbols
	});

	// 24.3.2 JSON.stringify(value [, replacer [, space]])
	$JSON && $export($export.S + $export.F * (!USE_NATIVE || $fails(function(){
	  var S = $Symbol();
	  // MS Edge converts symbol values to JSON as {}
	  // WebKit converts symbol values to JSON as null
	  // V8 throws on boxed symbols
	  return _stringify([S]) != '[null]' || _stringify({a: S}) != '{}' || _stringify(Object(S)) != '{}';
	})), 'JSON', {
	  stringify: function stringify(it){
	    if(it === undefined || isSymbol(it))return; // IE8 returns string on undefined
	    var args = [it]
	      , i    = 1
	      , replacer, $replacer;
	    while(arguments.length > i)args.push(arguments[i++]);
	    replacer = args[1];
	    if(typeof replacer == 'function')$replacer = replacer;
	    if($replacer || !isArray(replacer))replacer = function(key, value){
	      if($replacer)value = $replacer.call(this, key, value);
	      if(!isSymbol(value))return value;
	    };
	    args[1] = replacer;
	    return _stringify.apply($JSON, args);
	  }
	});

	// 19.4.3.4 Symbol.prototype[@@toPrimitive](hint)
	$Symbol[PROTOTYPE][TO_PRIMITIVE] || __webpack_require__(46)($Symbol[PROTOTYPE], TO_PRIMITIVE, $Symbol[PROTOTYPE].valueOf);
	// 19.4.3.5 Symbol.prototype[@@toStringTag]
	setToStringTag($Symbol, 'Symbol');
	// 20.2.1.9 Math[@@toStringTag]
	setToStringTag(Math, 'Math', true);
	// 24.3.3 JSON[@@toStringTag]
	setToStringTag(global.JSON, 'JSON', true);

/***/ },
/* 87 */
/***/ function(module, exports, __webpack_require__) {

	var META     = __webpack_require__(72)('meta')
	  , isObject = __webpack_require__(49)
	  , has      = __webpack_require__(57)
	  , setDesc  = __webpack_require__(47).f
	  , id       = 0;
	var isExtensible = Object.isExtensible || function(){
	  return true;
	};
	var FREEZE = !__webpack_require__(52)(function(){
	  return isExtensible(Object.preventExtensions({}));
	});
	var setMeta = function(it){
	  setDesc(it, META, {value: {
	    i: 'O' + ++id, // object ID
	    w: {}          // weak collections IDs
	  }});
	};
	var fastKey = function(it, create){
	  // return primitive with prefix
	  if(!isObject(it))return typeof it == 'symbol' ? it : (typeof it == 'string' ? 'S' : 'P') + it;
	  if(!has(it, META)){
	    // can't set metadata to uncaught frozen object
	    if(!isExtensible(it))return 'F';
	    // not necessary to add metadata
	    if(!create)return 'E';
	    // add missing metadata
	    setMeta(it);
	  // return object ID
	  } return it[META].i;
	};
	var getWeak = function(it, create){
	  if(!has(it, META)){
	    // can't set metadata to uncaught frozen object
	    if(!isExtensible(it))return true;
	    // not necessary to add metadata
	    if(!create)return false;
	    // add missing metadata
	    setMeta(it);
	  // return hash weak collections IDs
	  } return it[META].w;
	};
	// add metadata on freeze-family methods calling
	var onFreeze = function(it){
	  if(FREEZE && meta.NEED && isExtensible(it) && !has(it, META))setMeta(it);
	  return it;
	};
	var meta = module.exports = {
	  KEY:      META,
	  NEED:     false,
	  fastKey:  fastKey,
	  getWeak:  getWeak,
	  onFreeze: onFreeze
	};

/***/ },
/* 88 */
/***/ function(module, exports, __webpack_require__) {

	var global         = __webpack_require__(42)
	  , core           = __webpack_require__(43)
	  , LIBRARY        = __webpack_require__(40)
	  , wksExt         = __webpack_require__(83)
	  , defineProperty = __webpack_require__(47).f;
	module.exports = function(name){
	  var $Symbol = core.Symbol || (core.Symbol = LIBRARY ? {} : global.Symbol || {});
	  if(name.charAt(0) != '_' && !(name in $Symbol))defineProperty($Symbol, name, {value: wksExt.f(name)});
	};

/***/ },
/* 89 */
/***/ function(module, exports, __webpack_require__) {

	var getKeys   = __webpack_require__(62)
	  , toIObject = __webpack_require__(64);
	module.exports = function(object, el){
	  var O      = toIObject(object)
	    , keys   = getKeys(O)
	    , length = keys.length
	    , index  = 0
	    , key;
	  while(length > index)if(O[key = keys[index++]] === el)return key;
	};

/***/ },
/* 90 */
/***/ function(module, exports, __webpack_require__) {

	// all enumerable object keys, includes symbols
	var getKeys = __webpack_require__(62)
	  , gOPS    = __webpack_require__(91)
	  , pIE     = __webpack_require__(92);
	module.exports = function(it){
	  var result     = getKeys(it)
	    , getSymbols = gOPS.f;
	  if(getSymbols){
	    var symbols = getSymbols(it)
	      , isEnum  = pIE.f
	      , i       = 0
	      , key;
	    while(symbols.length > i)if(isEnum.call(it, key = symbols[i++]))result.push(key);
	  } return result;
	};

/***/ },
/* 91 */
/***/ function(module, exports) {

	exports.f = Object.getOwnPropertySymbols;

/***/ },
/* 92 */
/***/ function(module, exports) {

	exports.f = {}.propertyIsEnumerable;

/***/ },
/* 93 */
/***/ function(module, exports, __webpack_require__) {

	// 7.2.2 IsArray(argument)
	var cof = __webpack_require__(66);
	module.exports = Array.isArray || function isArray(arg){
	  return cof(arg) == 'Array';
	};

/***/ },
/* 94 */
/***/ function(module, exports, __webpack_require__) {

	// fallback for IE11 buggy Object.getOwnPropertyNames with iframe and window
	var toIObject = __webpack_require__(64)
	  , gOPN      = __webpack_require__(95).f
	  , toString  = {}.toString;

	var windowNames = typeof window == 'object' && window && Object.getOwnPropertyNames
	  ? Object.getOwnPropertyNames(window) : [];

	var getWindowNames = function(it){
	  try {
	    return gOPN(it);
	  } catch(e){
	    return windowNames.slice();
	  }
	};

	module.exports.f = function getOwnPropertyNames(it){
	  return windowNames && toString.call(it) == '[object Window]' ? getWindowNames(it) : gOPN(toIObject(it));
	};


/***/ },
/* 95 */
/***/ function(module, exports, __webpack_require__) {

	// 19.1.2.7 / 15.2.3.4 Object.getOwnPropertyNames(O)
	var $keys      = __webpack_require__(63)
	  , hiddenKeys = __webpack_require__(73).concat('length', 'prototype');

	exports.f = Object.getOwnPropertyNames || function getOwnPropertyNames(O){
	  return $keys(O, hiddenKeys);
	};

/***/ },
/* 96 */
/***/ function(module, exports, __webpack_require__) {

	var pIE            = __webpack_require__(92)
	  , createDesc     = __webpack_require__(55)
	  , toIObject      = __webpack_require__(64)
	  , toPrimitive    = __webpack_require__(54)
	  , has            = __webpack_require__(57)
	  , IE8_DOM_DEFINE = __webpack_require__(50)
	  , gOPD           = Object.getOwnPropertyDescriptor;

	exports.f = __webpack_require__(51) ? gOPD : function getOwnPropertyDescriptor(O, P){
	  O = toIObject(O);
	  P = toPrimitive(P, true);
	  if(IE8_DOM_DEFINE)try {
	    return gOPD(O, P);
	  } catch(e){ /* empty */ }
	  if(has(O, P))return createDesc(!pIE.f.call(O, P), O[P]);
	};

/***/ },
/* 97 */
/***/ function(module, exports) {

	

/***/ },
/* 98 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(88)('asyncIterator');

/***/ },
/* 99 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(88)('observable');

/***/ },
/* 100 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = { "default": __webpack_require__(101), __esModule: true };

/***/ },
/* 101 */
/***/ function(module, exports, __webpack_require__) {

	var core  = __webpack_require__(43)
	  , $JSON = core.JSON || (core.JSON = {stringify: JSON.stringify});
	module.exports = function stringify(it){ // eslint-disable-line no-unused-vars
	  return $JSON.stringify.apply($JSON, arguments);
	};

/***/ },
/* 102 */
/***/ function(module, exports) {

	module.exports = require("lodash");

/***/ },
/* 103 */
/***/ function(module, exports) {

	module.exports = require("jsonwebtoken");

/***/ },
/* 104 */
/***/ function(module, exports) {

	"use strict";

	module.exports = "<html lang=\"en\">\n<head>\n  <title>Auth0 - Protocol Debugger</title>\n  <meta charset=\"UTF-8\">\n  <meta http-equiv=\"X-UA-Compatible\" content=\"IE=Edge\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n  <link rel=\"shortcut icon\" href=\"https://cdn.auth0.com/styleguide/4.6.13/lib/logos/img/favicon.png\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"https://cdn.auth0.com/styles/zocial.min.css\">\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"https://cdn.auth0.com/manage/v0.3.1715/css/index.min.css\">\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"https://cdn.auth0.com/styleguide/4.6.13/index.css\">\n  <link rel=\"stylesheet\" href=\"//cdnjs.cloudflare.com/ajax/libs/highlight.js/9.7.0/styles/github.min.css\">\n  <script src=\"//cdnjs.cloudflare.com/ajax/libs/highlight.js/9.7.0/highlight.min.js\"></script>\n  <style type=\"text/css\">\n    p.controls-info {\n      font-size: 13px;\n      color: #000;\n      opacity: .56;\n      line-height: 18px;\n      margin: 8px 0 0 0;\n      clear: both;\n    }\n    code.xml {\n      color: black !important;\n      background-color: #fbfbfb !important;\n      margin-top: -25px !important;\n      margin-bottom: -51px !important;\n    }\n    pre.json-object {\n      background-color: #fbfbfb;\n      border: 1px solid #f1f1f1;\n      border-radius: 0px;\n      padding: 10px 10px;\n      font-size: 12px;\n    }\n    .json-object .json-key {\n      color: #16214D;\n    }\n    .json-object .json-value {\n      color: #01B48F;\n    }\n    .json-object .json-string {\n      color: #EB5424;\n    }\n  </style>\n</head>\n<body>\n<div id=\"app\">\n  <div>\n    <header class=\"dashboard-header\">\n      <nav role=\"navigation\" class=\"navbar navbar-default\">\n        <div class=\"container\">\n          <div class=\"navbar-header\">\n            <h1 class=\"navbar-brand\" style=\"padding-top: 0px;\"><a href=\"https://manage.auth0.com\"><span>Auth0</span></a></h1>\n          </div>\n          <div id=\"navbar-collapse\" class=\"collapse navbar-collapse\">\n            <ul class=\"nav navbar-nav navbar-right\">\n              <li><a target=\"_blank\" href=\"https://auth0.com/support\">Help &amp; Support</a></li>\n              <li><a target=\"_blank\" href=\"https://auth0.com/docs\">Documentation</a></li>\n            </ul>\n          </div>\n        </div>\n      </nav>\n    </header>\n    <div class=\"container\">\n      <div class=\"row\">\n        <div class=\"col-xs-12\">\n          <div class=\"row\">\n            <div class=\"col-xs-12\">\n              <h1 class=\"pull-left\" style=\"padding-top: 10px;\">Protocol Debugger</h1>\n            </div>\n          </div>\n          <div class=\"row\">\n            <div class=\"col-xs-12\">\n            \t<div class=\"widget-title title-with-nav-bars\">\n            \t\t<ul id=\"tabs\" class=\"nav nav-tabs\">\n            \t\t\t<li class=\"active\"><a data-toggle=\"tab\" href=\"#login\"><span class=\"tab-title\">Login</span></a></li>\n              \t\t<li><a data-toggle=\"tab\" href=\"#request\"><span class=\"tab-title\">Request</span></a></li>\n            \t\t</ul>\n            \t</div>\n            \t<div id=\"content-area\" class=\"tab-content\">\n                <div id=\"login\" class=\"tab-pane active\">\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div class=\"alert alert-warning\">Rendering (including of hash fragment, client credentials ...) happens on the server, which means that in some cases your tokens might be sent to the webtask hosting this page. You can find the implementation <a href=\"https://github.com/sandrinodimattia/auth-protocol-debugger\">on GitHub</a>.</div>\n                    </div>\n                    <div class=\"col-xs-12\">\n                      <button id=\"reset_settings\" class=\"btn btn-success\">Clear Settings</button>\n                      <p class=\"controls-info\">Hit this button if you want to remove everything from local storage.</p>\n                    </div>\n                    <div class=\"col-xs-12\" style=\"margin-top: 25px\">\n                      <div>\n                        <div class=\"widget-title title-with-nav-bars\">\n                      \t\t<ul id=\"login-tabs\" class=\"nav nav-tabs\">\n                      \t\t\t<li class=\"active\"><a data-toggle=\"tab\" href=\"#configuration\"><span class=\"tab-title\">Configuration</span></a></li>\n                        \t\t<li><a data-toggle=\"tab\" href=\"#oauth2\"><span class=\"tab-title\">OAuth2 / OIDC</span></a></li>\n                        \t\t<li><a data-toggle=\"tab\" href=\"#other-flows\"><span class=\"tab-title\">Other Flows</span></a></li>\n                      \t\t</ul>\n                      \t</div>\n                      \t<div id=\"login-content-area\" class=\"tab-content\">\n                          <div id=\"configuration\" class=\"tab-pane active\">\n                            <p>Enter your account settings and additional application settings here (these will be persisted in localstorage).</p>\n                            <form class=\"form-horizontal col-xs-12\">\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Domain</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"domain\" type=\"text\" class=\"form-control\" value=\"you.auth0.com\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Client ID</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"client_id\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Client Secret</label>\n                                <div class=\"col-xs-6\">\n                                  <input id=\"client_secret\" type=\"password\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Optional: Not all clients have a secret (eg: Mobile, SPA, Public). Don't store any production secrets here.</p>\n                                </div>\n                                <div class=\"col-xs-4\">\n                                  <div class=\"ui-switch ui-switch-labeled ui-switch-xl\">\n                                    <input id=\"save_client_secret\" type=\"checkbox\" />\n                                    <label data-label-true=\"Save in Local Storage\" data-label-false=\"Don't Save in Local Storage\" class=\"status\"></label>\n                                  </div>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Callback URL</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"callback_url\" readonly type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Make sure you configure this as the Callback Url on your client.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">SSO</label>\n                                <div class=\"col-xs-3\">\n                                  <div class=\"ui-switch\">\n                                    <input id=\"use_sso\" type=\"checkbox\"/>\n                                    <label class=\"status\"></label>\n                                  </div>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">State</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"state\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">This might translate to RelayState or wctx depending on the protocol.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Connection</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"connection\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Sprecify the name of a connection to skip the login page (eg: <strong>google-oauth2</strong>).</p>\n                                </div>\n                              </div>\n                            </form>\n                          </div>\n                          <div id=\"oauth2\" class=\"tab-pane\">\n                            <div class=\"alert alert-info\">Specification: <a href=\"https://tools.ietf.org/html/rfc6749#section-1.3.3\">OAuth2</a></div>\n                            <h5>User Flows</h5>\n                            <button id=\"oidc_oauth2\" class=\"btn btn-primary\">OAuth2 / OIDC Login</button>\n                            <button id=\"oauth2_code_exchange\" class=\"btn btn-primary\">OAuth2 Code Exchange</button>\n                            <button id=\"oauth2_refresh_token_exchange\" class=\"btn btn-primary\">OAuth2 Refresh Token Exchange</button>\n                            <p class=\"controls-info\">The exchanges will use the Client ID (and optionally Secret) from the Configuration tab.</p>\n                            <h5>Machine to Machine</h5>\n                            <button id=\"oauth2_client_credentials\" class=\"btn btn-primary\">OAuth2 Client Credentials</button>\n                            <p class=\"controls-info\">This will use the Client ID and Secret from the Configuration tab.</p>\n                            <h5>Resource Owner Password Credentials</h5>\n                            <form class=\"form-horizontal col-xs-12\">\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Username</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"username\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Password</label>\n                                <div class=\"col-xs-6\">\n                                  <input id=\"password\" type=\"password\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Optional: Only store passwords for test accounts here.</p>\n                                </div>\n                                <div class=\"col-xs-4\">\n                                  <div class=\"ui-switch ui-switch-labeled ui-switch-xl\">\n                                    <input id=\"save_password\" type=\"checkbox\" />\n                                    <label data-label-true=\"Save in Local Storage\" data-label-false=\"Don't Save in Local Storage\" class=\"status\"></label>\n                                  </div>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Device</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"device\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">This field is here for legacy purposes. It's not part of the spec.</p>\n                                </div>\n                              </div>\n                            </form>\n                            <button id=\"oauth2_password_grant\" class=\"btn btn-primary\">Password Grant</button>\n                            <button id=\"oauth2_ro\" class=\"btn btn-primary\">Resource Owner Endpoint</button>\n                            <p class=\"controls-info\">The Resource Owner Endpoint is here for legacy purposes. It's not part of the spec.</p>\n                            <h5>Delegation</h5>\n                            <p class=\"controls-info\">Not part of the spec - this is here for legacy purposes only.</p>\n                            <form class=\"form-horizontal col-xs-12\">\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">ID Token</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"delegation_id_token\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Refresh Token</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"delegation_refresh_token\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Target Client ID</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"delegation_target\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                            </form>\n                            <button id=\"oauth2_delegation\" class=\"btn btn-primary\">Delegation</button>\n                            <h5>Settings</h5>\n                            <p>The following settings might behave differently if you're using OAuth2 as a Service (Preview)</p>\n                            <form class=\"form-horizontal col-xs-12\">\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">PKCE</label>\n                                <div class=\"col-xs-10\">\n                                  <div class=\"ui-switch\">\n                                    <input id=\"use_pkce\" type=\"checkbox\"/>\n                                    <label class=\"status\"></label>\n                                  </div>\n                                  <p class=\"controls-info\">The PKCE (Proof Key for Code Exchange by OAuth Public Clients) or Hybrid Flow is a better alternative to the implicit flow for Mobile Apps. In Auth0, make sure you set the client type to \"Native\".</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Audience</label>\n                                <div class=\"col-xs-7\">\n                                  <input id=\"audience\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Only required when you need an access token.</p>\n                                </div>\n                                <div class=\"col-xs-3\">\n                                  <div class=\"ui-switch ui-switch-labeled ui-switch-md\">\n                                    <input id=\"use_audience\" type=\"checkbox\" />\n                                    <label data-label-true=\"Save in Local Storage\" data-label-false=\"Use Audience\" class=\"status\"></label>\n                                  </div>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Authorization Code</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"authorization_code\" type=\"text\" class=\"form-control\" value=\"{{authorization_code}}\">\n                                  <p class=\"controls-info\">Set the response type to <strong>code</strong> and then press the <strong>OIDC / OAuth2</strong> button to get an authorization code.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Code Verifier</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"code_verifier\" type=\"text\" class=\"form-control\" value=\"{{code_verifier}}\">\n                                  <p class=\"controls-info\">If you're using <strong>PKCE</strong>, this is what will be used instead of the Client Secret.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Refresh Token</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"refresh_token\" type=\"text\" class=\"form-control\" value=\"{{refresh_token}}\">\n                                  <p class=\"controls-info\">Set the response type to <strong>code</strong>, request the <strong>offline_access</strong> scope and then press the <strong>OIDC / OAuth2</strong> button to get an authorization code.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Response Type</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"response_type\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">You can try a mix of <strong>code</strong>, <strong>id_token</strong>, <strong>token</strong></p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Response Mode</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"response_mode\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">You can try something like <strong>fragment</strong>, <strong>query</strong> or <strong>form_post</strong></p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Scope</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"scope\" type=\"text\" class=\"form-control\" value=\"openid name email\">\n                                  <p class=\"controls-info\">You can try something like <strong>openid name email read:appointments</strong></p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Prompt</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"prompt\" type=\"text\" class=\"form-control\" value=\"openid name email\">\n                                  <p class=\"controls-info\">You can try something like <strong>consent</strong> or <strong>login</strong></p>\n                                </div>\n                              </div>\n                            </form>\n                          </div>\n                          <div id=\"other-flows\" class=\"tab-pane\">\n                            <button id=\"saml\" class=\"btn btn-primary\">SAML</button>\n                            <button id=\"wsfed\" class=\"btn btn-primary\">WS-Federation</button>\n                            <h5>Logout</h5>\n                            <button id=\"logout\" class=\"btn btn-primary\">Logout</button>\n                            <button id=\"logout-federated\" class=\"btn btn-primary\">Logout (Federated)</button>\n                            <h5>SSO</h5>\n                            <button id=\"sso-data\" class=\"btn btn-primary\">Get SSO Data</button>\n                            <div id=\"sso-data-output\"></div>\n                          </div>\n                        </div>\n                      </div>\n                    </div>\n                  </div>\n                </div>\n            \t\t<div id=\"request\" class=\"tab-pane\">\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Details</h5>\n                        <form class=\"form-horizontal col-xs-12\">\n                          <div class=\"form-group\"><label class=\"col-xs-1 control-label\">Method</label>\n                            <div class=\"col-xs-11\"><input type=\"text\" readonly=\"\" class=\"form-control\" value=\"{{method}}\"></div>\n                          </div>\n                          <div class=\"form-group\"><label class=\"col-xs-1 control-label\">Url</label>\n                            <div class=\"col-xs-11\"><input type=\"text\" readonly=\"\" class=\"form-control\" value=\"{{baseUrl}}\"></div>\n                          </div>\n                        </form>\n                      </div>\n                    </div>\n                  </div>\n                  {{#if body}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Body</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{body}}}</pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  {{#if id_token}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>ID Token</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{id_token}}}</pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  {{#if access_token}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Access Token</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{access_token}}}</pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  <div id=\"hash_fragment\"></div>\n                  {{#if samlResponse}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>SAML Response</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre>\n                        <code class=\"xml\">{{{samlResponse}}}</code>\n                      </pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  {{#if wsFedResult}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>WS-Federation Result</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre>\n                        <code class=\"xml\">{{{wsFedResult}}}</code>\n                      </pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  {{#if query}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Query</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{query}}}</pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Headers</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{headers}}}</pre>\n                    </div>\n                  </div>\n            \t\t</div>\n            \t\t<div id=\"login\" class=\"tab-pane\">\n            \t\t</div>\n            \t</div>\n            </div>\n          </div>\n        </div>\n      </div>\n    </div>\n  </div>\n  <div id=\"modal-dialog\" tabindex=\"-1\" role=\"dialog\" aria-hidden=\"true\" class=\"modal\">\n    <div class=\"modal-dialog\">\n      <div class=\"modal-content\">\n        <div class=\"modal-header has-border\">\n          <button type=\"button\" data-dismiss=\"modal\" class=\"close\"><span aria-hidden=\"true\">\xD7</span><span class=\"sr-only\">Close</span></button>\n          <h4 id=\"modal-title\" class=\"modal-title\"></h4>\n        </div>\n        <div id=\"modal-body\" class=\"modal-body\"></div>\n        <div class=\"modal-footer\">\n          <button data-dismiss=\"modal\" id=\"close-modal\" type=\"button\" class=\"btn btn-primary\">Close</button>\n        </div>\n      </div>\n    </div>\n  </div>\n</div>\n<script src=\"//cdnjs.cloudflare.com/ajax/libs/jquery/1.11.3/jquery.js\"></script>\n<script src=\"//cdn.auth0.com/w2/auth0-6.js\"></script>\n<script type=\"text/javascript\" src=\"//cdn.auth0.com/manage/v0.3.1715/js/bundle.js\"></script>\n<script>hljs.initHighlightingOnLoad();</script>\n<script type=\"text/javascript\">\nfunction read() {\n  $('#audience').val(localStorage.getItem('auth_debugger_audience'));\n  $('#callback_url').val(window.location.protocol + \"//\" + window.location.hostname + (window.location.port ? ':' + window.location.port : '') + window.location.pathname);\n  $('#client_id').val(localStorage.getItem('auth_debugger_client_id') || 'IsTxQ7jAYAXL5r5HM4L1RMzsSG0UHeOy');\n  $('#client_secret').val(localStorage.getItem('auth_debugger_client_secret'));\n  $('#code_verifier').val(localStorage.getItem('auth_debugger_code_verifier'));\n  $('#connection').val(localStorage.getItem('auth_debugger_connection'));\n  $('#device').val(localStorage.getItem('auth_debugger_device'));\n  $('#domain').val(localStorage.getItem('auth_debugger_domain') || 'sandrino.auth0.com');\n  $('#password').val(localStorage.getItem('auth_debugger_password'));\n  $('#delegation_target').val(localStorage.getItem('auth_debugger_delegation_target'));\n  $('#prompt').val(localStorage.getItem('auth_debugger_prompt') || '');\n  $('#refresh_token').val(localStorage.getItem('auth_debugger_refresh_token'));\n  $('#response_mode').val(localStorage.getItem('auth_debugger_response_mode') || '');\n  $('#response_type').val(localStorage.getItem('auth_debugger_response_type') || 'token');\n  $('#save_client_secret').prop('checked', localStorage.getItem('auth_debugger_client_secret') && localStorage.getItem('auth_debugger_client_secret').length);\n  $('#save_password').prop('checked', localStorage.getItem('auth_debugger_password') && localStorage.getItem('auth_debugger_password').length);\n  $('#scope').val(localStorage.getItem('auth_debugger_scope') || 'openid name email nickname');\n  $('#state').val(localStorage.getItem('auth_debugger_state') || 'my-custom-state');\n  $('#username').val(localStorage.getItem('auth_debugger_username'));\n  if (localStorage.getItem('auth_debugger_use_audience') === \"1\") {\n    $('#use_audience').prop('checked', 'checked');\n  }\n  if (localStorage.getItem('auth_debugger_use_pkce') === \"1\") {\n    $('#use_pkce').prop('checked', 'checked');\n  }\n  if (localStorage.getItem('auth_debugger_use_sso') === \"1\") {\n    $('#use_sso').prop('checked', 'checked');\n  }\n}\nfunction save() {\n  localStorage.setItem('auth_debugger_audience', $('#audience').val());\n  localStorage.setItem('auth_debugger_client_id', $('#client_id').val());\n  localStorage.setItem('auth_debugger_client_secret', $('#save_client_secret').is(':checked') ? $('#client_secret').val() : '');\n  localStorage.setItem('auth_debugger_code_verifier', $('#code_verifier').val());\n  localStorage.setItem('auth_debugger_connection', $('#connection').val());\n  localStorage.setItem('auth_debugger_domain', $('#domain').val());\n  localStorage.setItem('auth_debugger_delegation_target', $('#delegation_target').val());\n  localStorage.setItem('auth_debugger_device', $('#device').val());\n  localStorage.setItem('auth_debugger_password', $('#save_password').is(':checked') ? $('#save_password').val() : '');\n  localStorage.setItem('auth_debugger_prompt', $('#prompt').val());\n  localStorage.setItem('auth_debugger_refresh_token', $('#refresh_token').val());\n  localStorage.setItem('auth_debugger_response_mode', $('#response_mode').val());\n  localStorage.setItem('auth_debugger_response_type', $('#response_type').val());\n  localStorage.setItem('auth_debugger_scope', $('#scope').val());\n  localStorage.setItem('auth_debugger_state', $('#state').val());\n  localStorage.setItem('auth_debugger_use_audience', $('#use_audience').is(':checked') ? \"1\" : \"0\");\n  localStorage.setItem('auth_debugger_use_pkce', $('#use_pkce').is(':checked') ? \"1\" : \"0\");\n  localStorage.setItem('auth_debugger_use_sso', $('#use_sso').is(':checked') ? \"1\" : \"0\");\n  localStorage.setItem('auth_debugger_username', $('#username').val());\n}\nfunction executeRequest(title, url, opt) {\n  save();\n  $('#modal-title').html(title);\n  $('#modal-body').html('Loading...');\n  $('#modal-dialog').modal({ show: true });\n  $.post(url, opt)\n    .done(function(data) {\n      data.request = opt;\n      if (data.refresh_token) {\n        localStorage.setItem('auth_debugger_refresh_token', data.refresh_token);\n      }\n      if (data.request.password) {\n        data.request.password = '*****************';\n      }\n      if (data.request.client_secret) {\n        data.request.client_secret = '*****************';\n      }\n      $.ajax({ type: \"POST\", url: '{{baseUrl}}/request', data: JSON.stringify(data), contentType: 'application/json' })\n        .done(function(data) {\n          $('#modal-body').html(data);\n          $('#modal-body').prepend($('<pre/>', { 'class':'json-object', 'html': 'POST ' + url }));\n        })\n        .fail(function(err) {\n          $('#modal-body').html('<p>Error decoding the response.</p>');\n          $('<pre/>', { 'class':'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#modal-body');\n        });\n    })\n    .fail(function(err) {\n      if (opt.password) {\n        opt.password = '*****************';\n      }\n      if (opt.client_secret) {\n        opt.client_secret = '*****************';\n      }\n      $.ajax({ type: \"POST\", url: '{{baseUrl}}/request', data: JSON.stringify({ request: opt, err: err }), contentType: 'application/json' })\n        .done(function(data) {\n          $('#modal-body').html(data);\n          $('#modal-body').prepend($('<pre/>', { 'class':'json-object', 'html': 'POST ' + url }));\n        })\n        .fail(function(err) {\n          $('#modal-body').html('<p>Error decoding the response.</p>');\n          $('<pre/>', { 'class':'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#modal-body');\n        });\n    });\n}\nif (!window.location.origin) {\n  window.location.origin = window.location.protocol + \"//\" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');\n}\nvar callbackUrl = window.location.origin + window.location.pathname;\n$(function () {\n  read();\n  if (\"{{method}}\" === 'POST' || (window.location.hash && window.location.hash.length > 1) || (window.location.search && window.location.search.length > 1 && window.location.search !== '?webtask_no_cache=1')) {\n    $('#tabs a[href=\"#request\"]').tab('show');\n  }\n  if (window.location.hash && window.location.hash.length > 1) {\n    $('#hash_fragment').load(window.location.origin + window.location.pathname + '/hash?' + window.location.hash.replace(/^#/,\"\"));\n  }\n  $('#saml').click(function(e) {\n    e.preventDefault();\n    save();\n    var url = 'https://' + $('#domain').val() + '/samlp/' + $('#client_id').val() + '?RelayState=' + encodeURIComponent($('#state').val());\n    url = url + '&redirect_uri=' + encodeURIComponent(callbackUrl);\n    if ($('#connection').val() && $('#connection').val().length) {\n      url = url + '&connection=' + encodeURIComponent($('#connection').val());\n    }\n    window.location.href = url;\n  });\n  $('#wsfed').click(function(e) {\n    e.preventDefault();\n    save();\n    var url = 'https://' + $('#domain').val() + '/wsfed/' + $('#client_id').val() + '?wctx=' + encodeURIComponent($('#state').val());\n    url = url + '&wreply=' + encodeURIComponent(callbackUrl);\n    if ($('#connection').val() && $('#connection').val().length) {\n      url = url + '&wtrealm=' + encodeURIComponent($('#connection').val());\n    }\n    window.location.href = url;\n  });\n  $('#logout').click(function(e) {\n    e.preventDefault();\n    save();\n    window.location.href = 'https://' + $('#domain').val() + '/v2/logout?client_id=' + $('#client_id').val() + '&returnTo=' + encodeURIComponent(callbackUrl);\n  });\n  $('#logout-federated').click(function(e) {\n    e.preventDefault();\n    save();\n    window.location.href = 'https://' + $('#domain').val() + '/v2/logout?federated&client_id=' + $('#client_id').val() + '&returnTo=' + encodeURIComponent(callbackUrl);\n  });\n  $('#reset_settings').click(function(e) {\n    e.preventDefault();\n    for (key in localStorage) {\n      if (key.indexOf('auth_debugger_') === 0) {\n        delete localStorage[key];\n      }\n    }\n    read();\n  });\n  $('#oauth2_client_credentials').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      audience: $('#audience').val(),\n      client_id: $('#client_id').val(),\n      client_secret: $('#client_secret').val(),\n      grant_type: 'client_credentials'\n    };\n    executeRequest('OAuth2 - Client Credentials', 'https://' + $('#domain').val() + '/oauth/token', opt);\n  });\n  $('#oauth2_code_exchange').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      client_id: $('#client_id').val(),\n      redirect_uri: callbackUrl,\n      code: $('#authorization_code').val(),\n      grant_type: 'authorization_code'\n    };\n    if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {\n      opt.audience = $('#audience').val();\n    }\n    if ($('#use_pkce').is(':checked')) {\n      opt.code_verifier = $('#code_verifier').val();\n    } else {\n      opt.client_secret = $('#client_secret').val();\n    }\n    executeRequest('OAuth2 - Authorization Code Exchange', 'https://' + $('#domain').val() + '/oauth/token', opt);\n  });\n  $('#oauth2_refresh_token_exchange').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      client_id: $('#client_id').val(),\n      refresh_token: $('#refresh_token').val(),\n      grant_type: 'refresh_token'\n    };\n    if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {\n      opt.audience = $('#audience').val();\n    }\n    if ($('#use_pkce').is(':checked')) {\n      opt.code_verifier = $('#code_verifier').val();\n    } else {\n      opt.client_secret = $('#client_secret').val();\n    }\n    executeRequest('OAuth2 - Refresh Token Exchange', 'https://' + $('#domain').val() + '/oauth/token', opt);\n  });\n  $('#oauth2_password_grant').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      client_id: $('#client_id').val(),\n      username: $('#username').val(),\n      password: $('#password').val(),\n      grant_type: 'password',\n      scope: $('#scope').val()\n    };\n    if ($('#connection').val() && $('#connection').val().length) {\n      opt.connection = $('#connection').val();\n    }\n    executeRequest('OAuth2 - Password Grant', 'https://' + $('#domain').val() + '/oauth/token', opt);\n  });\n  $('#oauth2_ro').click(function(e) {\n    e.preventDefault();\n    if ($('#use_sso').is(':checked')) {\n      save();\n      var auth0 = new Auth0({\n        domain: $('#domain').val(),\n        clientID: $('#client_id').val(),\n        callbackURL: callbackUrl\n      });\n      var options = {\n        state: $('#state').val(),\n        sso: $('#use_sso').is(':checked'),\n        username: $('#username').val(),\n        password: $('#password').val(),\n        connection: $('#connection').val(),\n        scope: $('#scope').val()\n      };\n      if ($('#device').val() && $('#device').val().length) {\n        options.device = $('#device').val();\n      }\n      return auth0.login(options);\n    }\n    var opt = {\n      client_id: $('#client_id').val(),\n      username: $('#username').val(),\n      password: $('#password').val(),\n      grant_type: 'password',\n      scope: $('#scope').val()\n    };\n    if ($('#connection').val() && $('#connection').val().length) {\n      opt.connection = $('#connection').val();\n    }\n    if ($('#device').val() && $('#device').val().length) {\n      opt.device = $('#device').val();\n    }\n    executeRequest('OAuth2 - Resource Owner', 'https://' + $('#domain').val() + '/oauth/ro', opt);\n  });\n  $('#oauth2_delegation').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      client_id: $('#client_id').val(),\n      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',\n      scope: $('#scope').val()\n    };\n    if ($('#delegation_target').val() && $('#delegation_target').val().length) {\n      opt.target = $('#delegation_target').val();\n    }\n    if ($('#delegation_id_token').val() && $('#delegation_id_token').val().length) {\n      opt.id_token = $('#delegation_id_token').val();\n    }\n    if ($('#delegation_refresh_token').val() && $('#delegation_refresh_token').val().length) {\n      opt.refresh_token = $('#delegation_refresh_token').val();\n    }\n    executeRequest('OAuth2 - Delegation', 'https://' + $('#domain').val() + '/delegation', opt);\n  });\n  $('#oidc_oauth2').click(function(e) {\n    e.preventDefault();\n    save();\n    // Don't do this in production. The client should always generate the verifier, and not rely on a remote server to do this.\n    $.get('{{baseUrl}}/pkce')\n      .done(function(data) {\n        var auth0 = new Auth0({\n          domain: $('#domain').val(),\n          clientID: $('#client_id').val(),\n          callbackURL: callbackUrl\n        });\n        var options = {\n          state: $('#state').val(),\n          sso: $('#use_sso').is(':checked'),\n        };\n        if ($('#use_pkce').is(':checked')) {\n          options.code_challenge = data.verifier_challenge;\n          options.code_challenge_method = 'S256';\n          localStorage.setItem('auth_debugger_code_verifier', data.verifier);\n        }\n        if ($('#scope').val() && $('#scope').val().length) {\n          options.scope = $('#scope').val();\n        }\n        if ($('#connection').val() && $('#connection').val().length) {\n          options.connection = $('#connection').val();\n        }\n        if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {\n          options.audience = $('#audience').val();\n        }\n        if ($('#response_type').val() && $('#response_type').val().length) {\n          options.response_type = $('#response_type').val();\n        }\n        if ($('#response_mode').val() && $('#response_mode').val().length) {\n          options.response_mode = $('#response_mode').val();\n        }\n        if ($('#prompt').val() && $('#prompt').val().length) {\n          options.prompt = $('#prompt').val();\n        }\n        auth0.login(options);\n      });\n  });\n  $('#sso-data').click(function(e) {\n    e.preventDefault();\n    save();\n    var auth0 = new Auth0({\n      domain: $('#domain').val(),\n      clientID: $('#client_id').val(),\n      callbackURL: callbackUrl\n    });\n    $('#sso-data-output').html('Loading...');\n    auth0.getSSOData(function(err, res) {\n      $.ajax({ type: \"POST\", url: '{{baseUrl}}/request', data: JSON.stringify({ error: err, response: res }), contentType: 'application/json' })\n        .done(function(data) {\n          $('#sso-data-output').html(data);\n        })\n        .fail(function(err) {\n          $('#sso-data-output').html('');\n          $('<pre/>', { 'class':'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#sso-data-output');\n        });\n    });\n  });\n});\n</script>\n</body>\n</html>\n";

/***/ },
/* 105 */
/***/ function(module, exports) {

	"use strict";

	module.exports = "\n{{#if request}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>Request</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{request}}}</pre>\n  </div>\n</div>\n{{/if}}\n{{#if response}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>Response</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{response}}}</pre>\n  </div>\n</div>\n{{/if}}\n{{#if hash}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>Hash Fragment</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{hash}}}</pre>\n  </div>\n</div>\n{{/if}}\n{{#if id_token}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>ID Token</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{id_token}}}</pre>\n  </div>\n</div>\n{{/if}}\n{{#if access_token}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>Access Token</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{access_token}}}</pre>\n  </div>\n</div>\n{{/if}}\n";

/***/ }
/******/ ]);