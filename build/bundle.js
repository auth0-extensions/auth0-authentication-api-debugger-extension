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

	var App = __webpack_require__(1);

	var port = process.env.PORT || 3000;

	App.listen(port, function () {
	    console.log('Server started on port', port);
	});

/***/ },
/* 1 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var path = __webpack_require__(2);
	var crypto = __webpack_require__(3);
	var express = __webpack_require__(4);
	var bodyParser = __webpack_require__(5);
	var handlebars = __webpack_require__(6);
	var Webtask = __webpack_require__(7);
	var expressTools = __webpack_require__(8);
	var metadata = __webpack_require__(49);

	var utils = __webpack_require__(50);
	var index = handlebars.compile(__webpack_require__(121));
	var partial = handlebars.compile(__webpack_require__(122));

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
/* 2 */
/***/ function(module, exports) {

	module.exports = require("path");

/***/ },
/* 3 */
/***/ function(module, exports) {

	module.exports = require("crypto");

/***/ },
/* 4 */
/***/ function(module, exports) {

	module.exports = require("express");

/***/ },
/* 5 */
/***/ function(module, exports) {

	module.exports = require("body-parser");

/***/ },
/* 6 */
/***/ function(module, exports) {

	module.exports = require("handlebars");

/***/ },
/* 7 */
/***/ function(module, exports) {

	module.exports = require("webtask-tools");

/***/ },
/* 8 */
/***/ function(module, exports, __webpack_require__) {

	const server = __webpack_require__(9);
	const urlHelpers = __webpack_require__(38);
	const middlewares = __webpack_require__(40);

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


/***/ },
/* 9 */
/***/ function(module, exports, __webpack_require__) {

	const tools = __webpack_require__(10);
	const Webtask = __webpack_require__(7);

	module.exports.createServer = function(cb) {
	  return Webtask.fromExpress(tools.createServer(cb));
	};


/***/ },
/* 10 */
/***/ function(module, exports, __webpack_require__) {

	const Webtask = __webpack_require__(7);

	const errors = __webpack_require__(11);
	const storage = __webpack_require__(19);

	const tools = module.exports = { };

	/*
	 * Errors exposed by the library.
	 */
	tools.ArgumentError = errors.ArgumentError;
	tools.ForbiddenError = errors.ForbiddenError;
	tools.HookTokenError = errors.HookTokenError;
	tools.ManagementApiError = errors.ManagementApiError;
	tools.NotFoundError = errors.NotFoundError;
	tools.UnauthorizedError = errors.UnauthorizedError;
	tools.ValidationError = errors.ValidationError;

	/*
	 * Helper for the Management Api.
	 */
	tools.managementApi = __webpack_require__(25);

	/*
	 * Storage helpers.
	 */
	tools.FileStorageContext = storage.FileStorageContext;
	tools.WebtaskStorageContext = storage.WebtaskStorageContext;

	/*
	 * Helpers that expose CRUD capablities to storage.
	 */
	tools.BlobRecordProvider = __webpack_require__(32);

	/*
	 * Helper that providers a configuration object containing one or more settings.
	 */
	tools.config = __webpack_require__(34);
	tools.configProvider = __webpack_require__(35);

	/*
	 * Bootstrap function to run initialize a server (connect, express, ...).
	 */
	tools.createServer = __webpack_require__(36).createServer;

	/*
	 * Validate a token for webtask hooks.
	 */
	tools.validateHookToken = __webpack_require__(37);

	/*
	 * Bootstrap function to run initialize an Express server.
	 */
	tools.createExpressServer = function createExpressServer(cb) {
	  return Webtask.fromExpress(tools.createServer(cb));
	};

	/*
	 * Bootstrap function to run initialize a Hapi server.
	 */
	tools.createHapiServer = function createHapiServer(cb) {
	  return Webtask.fromHapi(tools.createServer(cb));
	};


/***/ },
/* 11 */
/***/ function(module, exports, __webpack_require__) {

	module.exports.ArgumentError = __webpack_require__(12);
	module.exports.ForbiddenError = __webpack_require__(13);
	module.exports.HookTokenError = __webpack_require__(14);
	module.exports.ManagementApiError = __webpack_require__(15);
	module.exports.NotFoundError = __webpack_require__(16);
	module.exports.UnauthorizedError = __webpack_require__(17);
	module.exports.ValidationError = __webpack_require__(18);


/***/ },
/* 12 */
/***/ function(module, exports) {

	function ArgumentError(message) {
	  Error.call(this, message);
	  Error.captureStackTrace(this, this.constructor);
	  this.name = 'ArgumentError';
	  this.message = message;
	  this.status = 400;
	}

	ArgumentError.prototype = Object.create(Error.prototype);
	ArgumentError.prototype.constructor = ArgumentError;
	module.exports = ArgumentError;


/***/ },
/* 13 */
/***/ function(module, exports) {

	function ForbiddenError(message) {
	  Error.call(this, message);
	  Error.captureStackTrace(this, this.constructor);
	  this.name = 'ForbiddenError';
	  this.message = message;
	  this.status = 403;
	}

	ForbiddenError.prototype = Object.create(Error.prototype);
	ForbiddenError.prototype.constructor = ForbiddenError;
	module.exports = ForbiddenError;


/***/ },
/* 14 */
/***/ function(module, exports) {

	function HookTokenError(message, innerError) {
	  Error.call(this, message);
	  Error.captureStackTrace(this, this.constructor);
	  this.name = 'HookTokenError';
	  this.message = message;
	  this.status = 401;
	  this.innerError = innerError;
	}

	HookTokenError.prototype = Object.create(Error.prototype);
	HookTokenError.prototype.constructor = HookTokenError;
	module.exports = HookTokenError;


/***/ },
/* 15 */
/***/ function(module, exports) {

	function ManagementApiError(code, message, status) {
	  Error.call(this, message);
	  Error.captureStackTrace(this, this.constructor);
	  this.name = 'ManagementApiError';
	  this.code = code;
	  this.message = message;
	  this.status = status || 400;
	}

	ManagementApiError.prototype = Object.create(Error.prototype);
	ManagementApiError.prototype.constructor = ManagementApiError;
	module.exports = ManagementApiError;


/***/ },
/* 16 */
/***/ function(module, exports) {

	function NotFoundError(message) {
	  Error.call(this, message);
	  Error.captureStackTrace(this, this.constructor);
	  this.name = 'NotFoundError';
	  this.message = message;
	  this.status = 404;
	}

	NotFoundError.prototype = Object.create(Error.prototype);
	NotFoundError.prototype.constructor = NotFoundError;
	module.exports = NotFoundError;


/***/ },
/* 17 */
/***/ function(module, exports) {

	function UnauthorizedError(message) {
	  Error.call(this, message);
	  Error.captureStackTrace(this, this.constructor);
	  this.name = 'UnauthorizedError';
	  this.message = message;
	  this.status = 401;
	}

	UnauthorizedError.prototype = Object.create(Error.prototype);
	UnauthorizedError.prototype.constructor = UnauthorizedError;
	module.exports = UnauthorizedError;


/***/ },
/* 18 */
/***/ function(module, exports) {

	function ValidationError(message) {
	  Error.call(this, message);
	  Error.captureStackTrace(this, this.constructor);
	  this.name = 'ValidationError';
	  this.message = message;
	  this.status = 400;
	}

	ValidationError.prototype = Object.create(Error.prototype);
	ValidationError.prototype.constructor = ValidationError;
	module.exports = ValidationError;


/***/ },
/* 19 */
/***/ function(module, exports, __webpack_require__) {

	module.exports.FileStorageContext = __webpack_require__(20);
	module.exports.WebtaskStorageContext = __webpack_require__(24);


/***/ },
/* 20 */
/***/ function(module, exports, __webpack_require__) {

	const _ = __webpack_require__(21);
	const fs = __webpack_require__(22);
	const Promise = __webpack_require__(23);

	const ArgumentError = __webpack_require__(11).ArgumentError;

	/**
	 * Create a new FileStorageContext.
	 * @param {string} path The full path to the file.
	 * @param {Object} options The options object.
	 * @param {boolean} options.mergeWrites Merge the data from the local file with the new payload when writing a file.
	 *     (defaults to `true` if options is not defined).
	 * @param {Object} options.defaultData The default data to use when the file does not exist or is empty.
	 * @constructor
	 */
	function FileStorageContext(path, options) {
	  if (path === null || path === undefined) {
	    throw new ArgumentError('Must provide the path to the file');
	  }

	  if (typeof path !== 'string' || path.length === 0) {
	    throw new ArgumentError('The provided path is invalid: ' + path);
	  }

	  options = options || { mergeWrites: true };

	  this.path = path;
	  this.mergeWrites = options.mergeWrites;
	  this.defaultData = options.defaultData || {};
	}

	/**
	 * Read payload from the file.
	 * @return {object} The object parsed from the file.
	 */
	FileStorageContext.prototype.read = function() {
	  const ctx = this;
	  return new Promise(function readFileStorageContext(resolve, reject) {
	    fs.readFile(ctx.path, 'utf8', function(err, data) {
	      if (err) {
	        if (err.code === 'ENOENT') {
	          return resolve(ctx.defaultData);
	        }

	        return reject(err);
	      }
	      try {
	        if (data && data.length) {
	          return resolve(JSON.parse(data));
	        }

	        return resolve(ctx.defaultData);
	      } catch (e) {
	        return reject(e);
	      }
	    });
	  });
	};

	/**
	 * Write payload to the file.
	 * @param {object} payload The object to write.
	 */
	FileStorageContext.prototype.write = function(payload) {
	  const ctx = this;
	  var writePromise = Promise.resolve(payload);

	  if (ctx.mergeWrites) {
	    writePromise = writePromise.then(function(data) {
	      return ctx.read()
	        .then(function(originalData) {
	          return _.extend({ }, originalData, data);
	        });
	    });
	  }

	  return writePromise.then(function(data) {
	    return new Promise(function(resolve, reject) {
	      try {
	        return fs.writeFile(ctx.path, JSON.stringify(data, null, 2), 'utf8', function(err) {
	          if (err) {
	            return reject(err);
	          }

	          return resolve();
	        });
	      } catch (e) {
	        return reject(e);
	      }
	    });
	  });
	};

	/**
	 * Module exports.
	 * @type {function}
	 */
	module.exports = FileStorageContext;


/***/ },
/* 21 */
/***/ function(module, exports) {

	module.exports = require("lodash");

/***/ },
/* 22 */
/***/ function(module, exports) {

	module.exports = require("fs");

/***/ },
/* 23 */
/***/ function(module, exports) {

	module.exports = require("bluebird");

/***/ },
/* 24 */
/***/ function(module, exports, __webpack_require__) {

	const Promise = __webpack_require__(23);

	const ArgumentError = __webpack_require__(11).ArgumentError;

	/**
	 * Create a new WebtaskStorageContext.
	 * @param {Object} storage The Webtask storage object.
	 * @param {Object} options The options object.
	 * @param {int} options.force Disregard the possibility of a conflict.
	 * @param {Object} options.defaultData The default data to use when the file does not exist or is empty.
	 * @constructor
	 */
	function WebtaskStorageContext(storage, options) {
	  if (storage === null || storage === undefined) {
	    throw new ArgumentError('Must provide the Webtask storage object');
	  }

	  options = options || { force: 1 };

	  this.storage = storage;
	  this.options = options;
	  this.defaultData = options.defaultData || {};
	}

	/**
	 * Read payload from Webtask storage.
	 * @return {object} The object parsed from Webtask storage.
	 */
	WebtaskStorageContext.prototype.read = function() {
	  const ctx = this;
	  return new Promise(function readWebtaskStorageContext(resolve, reject) {
	    ctx.storage.get(function(err, data) {
	      if (err) {
	        return reject(err);
	      }

	      return resolve(data || ctx.defaultData);
	    });
	  });
	};

	/**
	 * Write data to Webtask storage.
	 * @param {object} data The object to write.
	 */
	WebtaskStorageContext.prototype.write = function(data) {
	  const ctx = this;
	  return new Promise(function(resolve, reject) {
	    ctx.storage.set(data, ctx.options, function(err) {
	      if (err) {
	        return reject(err);
	      }

	      return resolve();
	    });
	  });
	};

	/**
	 * Module exports.
	 * @type {function}
	 */
	module.exports = WebtaskStorageContext;


/***/ },
/* 25 */
/***/ function(module, exports, __webpack_require__) {

	const ms = __webpack_require__(26);
	const jwt = __webpack_require__(27);
	const auth0 = __webpack_require__(28);
	const Promise = __webpack_require__(23);
	const memoizer = __webpack_require__(29);
	const request = __webpack_require__(31);

	const ArgumentError = __webpack_require__(11).ArgumentError;
	const ManagementApiError = __webpack_require__(11).ManagementApiError;

	const getAccessToken = function(domain, clientId, clientSecret) {
	  return new Promise(function(resolve, reject) {
	    request
	      .post('https://' + domain + '/oauth/token')
	      .send({
	        audience: 'https://' + domain + '/api/v2/',
	        client_id: clientId,
	        client_secret: clientSecret,
	        grant_type: 'client_credentials'
	      })
	      .set('Accept', 'application/json')
	      .end(function(err, res) {
	        if (err && err.status === 401) {
	          return reject(new ManagementApiError('unauthorized', 'Invalid credentials for ' + clientId, err.status));
	        } else if (err && res && res.body && res.body.error) {
	          return reject(new ManagementApiError(res.body.error, res.body.error_description || res.body.error, err.status));
	        } else if (err) {
	          return reject(err);
	        }

	        if (!res.ok || !res.body.access_token) {
	          return reject(new ManagementApiError('unknown_error', 'Unknown error from Management Api or no access token was provided: ' + (res.text || res.status)));
	        }

	        return resolve(res.body.access_token);
	      });
	  });
	};

	const getAccessTokenCached = Promise.promisify(
	  memoizer({
	    load: function(domain, clientId, clientSecret, callback) {
	      getAccessToken(domain, clientId, clientSecret)
	        .then(function(accessToken) {
	          return callback(null, accessToken);
	        })
	        .catch(function(err) {
	          return callback(err);
	        });
	    },
	    hash: function(domain, clientId, clientSecret) {
	      return domain + '-' + clientId + '-' + clientSecret;
	    },
	    itemMaxAge: function(domain, clientId, clientSecret, accessToken) {
	      try {
	        const decodedToken = jwt.decode(accessToken);
	        const expiresIn = new Date(0);
	        expiresIn.setUTCSeconds(decodedToken.exp);
	        const now = new Date().valueOf();
	        return (expiresIn.valueOf() - now) - 10000;
	      } catch (e) {
	        return 1000;
	      }
	    },
	    max: 100,
	    maxAge: ms('1h')
	  }
	));

	module.exports.getAccessToken = getAccessToken;
	module.exports.getAccessTokenCached = getAccessTokenCached;
	module.exports.getClient = function(options) {
	  if (options === null || options === undefined) {
	    throw new ArgumentError('An options object must be provided');
	  }

	  if (options.domain === null || options.domain === undefined) {
	    throw new ArgumentError('An options object must contain the domain');
	  }

	  if (typeof options.domain !== 'string' || options.domain.length === 0) {
	    throw new ArgumentError('The provided domain is invalid: ' + options.domain);
	  }

	  if (options.accessToken) {
	    if (typeof options.accessToken !== 'string' || options.accessToken.length === 0) {
	      throw new ArgumentError('The provided accessToken is invalid');
	    }

	    return Promise.resolve(new auth0.ManagementClient({ domain: options.domain, token: options.accessToken }));
	  }

	  if (options.clientId === null || options.clientId === undefined) {
	    throw new ArgumentError('An options object must contain the clientId');
	  }

	  if (typeof options.clientId !== 'string' || options.clientId.length === 0) {
	    throw new ArgumentError('The provided clientId is invalid: ' + options.clientId);
	  }

	  if (options.clientSecret === null || options.clientSecret === undefined) {
	    throw new ArgumentError('An options object must contain the clientSecret');
	  }

	  if (typeof options.clientSecret !== 'string' || options.clientSecret.length === 0) {
	    throw new ArgumentError('The provided clientSecret is invalid');
	  }

	  return getAccessTokenCached(options.domain, options.clientId, options.clientSecret)
	    .then(function(token) {
	      return new auth0.ManagementClient({ domain: options.domain, token: token });
	    });
	};


/***/ },
/* 26 */
/***/ function(module, exports) {

	module.exports = require("ms");

/***/ },
/* 27 */
/***/ function(module, exports) {

	module.exports = require("jsonwebtoken");

/***/ },
/* 28 */
/***/ function(module, exports) {

	module.exports = require("auth0");

/***/ },
/* 29 */
/***/ function(module, exports, __webpack_require__) {

	const LRU        = __webpack_require__(30);
	const _          = __webpack_require__(21);
	const lru_params = [ 'max', 'maxAge', 'length', 'dispose', 'stale' ];

	module.exports = function (options) {
	  const cache      = new LRU(_.pick(options, lru_params));
	  const load       = options.load;
	  const hash       = options.hash;
	  const bypass     = options.bypass;
	  const itemMaxAge = options.itemMaxAge;
	  const loading    = new Map();

	  if (options.disable) {
	    return load;
	  }

	  const result = function () {
	    const args       = _.toArray(arguments);
	    const parameters = args.slice(0, -1);
	    const callback   = args.slice(-1).pop();
	    const self       = this;

	    var key;

	    if (bypass && bypass.apply(self, parameters)) {
	      return load.apply(self, args);
	    }

	    if (parameters.length === 0 && !hash) {
	      //the load function only receives callback.
	      key = '_';
	    } else {
	      key = hash.apply(self, parameters);
	    }

	    var fromCache = cache.get(key);

	    if (fromCache) {
	      return callback.apply(null, [null].concat(fromCache));
	    }

	    if (!loading.get(key)) {
	      loading.set(key, []);

	      load.apply(self, parameters.concat(function (err) {
	        const args = _.toArray(arguments);

	        //we store the result only if the load didn't fail.
	        if (!err) {
	          const result = args.slice(1);
	          if (itemMaxAge) {
	            cache.set(key, result, itemMaxAge.apply(self, parameters.concat(result)));
	          } else {
	            cache.set(key, result);
	          }
	        }

	        //immediately call every other callback waiting
	        loading.get(key).forEach(function (callback) {
	          callback.apply(null, args);
	        });

	        loading.delete(key);
	        /////////

	        callback.apply(null, args);
	      }));
	    } else {
	      loading.get(key).push(callback);
	    }
	  };

	  result.keys = cache.keys.bind(cache);

	  return result;
	};


	module.exports.sync = function (options) {
	  const cache = new LRU(_.pick(options, lru_params));
	  const load = options.load;
	  const hash = options.hash;
	  const disable = options.disable;
	  const bypass = options.bypass;
	  const self = this;
	  const itemMaxAge = options.itemMaxAge;

	  if (disable) {
	    return load;
	  }

	  const result = function () {
	    var args = _.toArray(arguments);

	    if (bypass && bypass.apply(self, arguments)) {
	      return load.apply(self, arguments);
	    }

	    var key = hash.apply(self, args);

	    var fromCache = cache.get(key);

	    if (fromCache) {
	      return fromCache;
	    }

	    const result = load.apply(self, args);
	    if (itemMaxAge) {
	      cache.set(key, result, itemMaxAge.apply(self, args.concat([ result ])));
	    } else {
	      cache.set(key, result);
	    }

	    return result;
	  };

	  result.keys = cache.keys.bind(cache);

	  return result;
	};


/***/ },
/* 30 */
/***/ function(module, exports) {

	module.exports = require("lru-cache");

/***/ },
/* 31 */
/***/ function(module, exports) {

	module.exports = require("superagent");

/***/ },
/* 32 */
/***/ function(module, exports, __webpack_require__) {

	const _ = __webpack_require__(21);
	const uuid = __webpack_require__(33);
	const ArgumentError = __webpack_require__(11).ArgumentError;
	const NotFoundError = __webpack_require__(11).NotFoundError;
	const ValidationError = __webpack_require__(11).ValidationError;

	const getDataForCollection = function(storageContext, collectionName) {
	  return storageContext.read(collectionName)
	    .then(function(data) {
	      data[collectionName] = data[collectionName] || [];
	      return data;
	    });
	};

	/**
	 * Create a new BlobRecordProvider.
	 * @param {Object} storageContext The storage context.
	 * @constructor
	 */
	function BlobRecordProvider(storageContext) {
	  if (storageContext === null || storageContext === undefined) {
	    throw new ArgumentError('Must provide a storage context');
	  }

	  this.storageContext = storageContext;
	}

	/**
	 * Get all records for a collection.
	 * @param {string} collectionName The name of the collection.
	 * @return {Array} The records.
	 */
	BlobRecordProvider.prototype.getAll = function(collectionName) {
	  return getDataForCollection(this.storageContext, collectionName)
	    .then(function(data) {
	      return data[collectionName];
	    });
	};

	/**
	 * Get a single record from a collection.
	 * @param {string} collectionName The name of the collection.
	 * @param {string} identifier The identifier of the record.
	 * @return {Object} The record.
	 */
	BlobRecordProvider.prototype.get = function(collectionName, identifier) {
	  return this.getAll(collectionName)
	    .then(function(records) {
	      const record = _.find(records, function(r) { return r._id === identifier });
	      if (!record) {
	        return Promise.reject(
	          new NotFoundError('The record ' + identifier + ' in ' + collectionName + ' does not exist.')
	        );
	      }

	      return record;
	    });
	};

	/**
	 * Create a record in a collection.
	 * @param {string} collectionName The name of the collection.
	 * @param {Object} record The record.
	 * @return {Object} The record.
	 */
	BlobRecordProvider.prototype.create = function(collectionName, record) {
	  const storageContext = this.storageContext;
	  return getDataForCollection(storageContext, collectionName)
	    .then(function(data) {
	      if (!record._id) {
	        record._id = uuid.v4();
	      }

	      const index = _.findIndex(data[collectionName], function(r) { return r._id === record._id; });
	      if (index > -1) {
	        return Promise.reject(
	          new ValidationError('The record ' + record._id + ' in ' + collectionName + ' already exists.')
	        );
	      }

	      // Add to dataset.
	      data[collectionName].push(record);

	      // Save.
	      return storageContext.write(data)
	        .then(function() {
	          return record;
	        });
	    });
	};

	/**
	 * Update a record in a collection.
	 * @param {string} collectionName The name of the collection.
	 * @param {string} identifier The identifier of the record to update.
	 * @param {Object} record The record.
	 * @param {boolean} upsert Flag allowing to upsert if the record does not exist.
	 * @return {Object} The record.
	 */
	BlobRecordProvider.prototype.update = function(collectionName, identifier, record, upsert) {
	  const storageContext = this.storageContext;
	  return getDataForCollection(storageContext, collectionName)
	    .then(function(data) {
	      const index = _.findIndex(data[collectionName], function(r) { return r._id === identifier; });
	      if (index < 0 && !upsert) {
	        throw new NotFoundError('The record ' + identifier + ' in ' + collectionName + ' does not exist.');
	      }

	      // Update record.
	      const updatedRecord = _.extend({ _id: identifier }, index < 0 ? { } : data[collectionName][index], record);
	      if (index < 0) {
	        data[collectionName].push(updatedRecord);
	      } else {
	        data[collectionName][index] = updatedRecord;
	      }

	      // Save.
	      return storageContext.write(data)
	        .then(function() {
	          return updatedRecord;
	        });
	    });
	};

	/**
	 * Delete a record in a collection.
	 * @param {string} collectionName The name of the collection.
	 * @param {string} identifier The identifier of the record to update.
	 */
	BlobRecordProvider.prototype.delete = function(collectionName, identifier) {
	  const storageContext = this.storageContext;
	  return getDataForCollection(storageContext, collectionName)
	    .then(function(data) {
	      const index = _.findIndex(data[collectionName], function(r) { return r._id === identifier; });
	      if (index < 0) {
	        return false;
	      }

	      // Remove the record.
	      data[collectionName].splice(index, 1);

	      // Save.
	      return storageContext.write(data)
	        .then(function() {
	          return true;
	        });
	    });
	};

	/**
	 * Module exports.
	 * @type {function}
	 */
	module.exports = BlobRecordProvider;


/***/ },
/* 33 */
/***/ function(module, exports) {

	module.exports = require("node-uuid");

/***/ },
/* 34 */
/***/ function(module, exports) {

	module.exports = function() {
	  var currentProvider = null;

	  const config = function(key) {
	    if (!currentProvider) {
	      throw new Error('A configuration provider has not been set');
	    }

	    return currentProvider(key);
	  };

	  config.setProvider = function(providerFunction) {
	    currentProvider = providerFunction;
	  };

	  return config;
	};


/***/ },
/* 35 */
/***/ function(module, exports, __webpack_require__) {

	const _ = __webpack_require__(21);
	const ArgumentError = __webpack_require__(11).ArgumentError;

	module.exports.fromWebtaskContext = function(webtaskContext) {
	  if (webtaskContext === null || webtaskContext === undefined) {
	    throw new ArgumentError('Must provide a webtask context');
	  }

	  const settings = _.assign({ }, process.env, webtaskContext.params, webtaskContext.secrets, {
	    NODE_ENV: 'production',
	    HOSTING_ENV: 'webtask'
	  });

	  return function getSettings(key) {
	    return settings[key];
	  };
	};


/***/ },
/* 36 */
/***/ function(module, exports, __webpack_require__) {

	const configProvider = __webpack_require__(35);

	module.exports.createServer = function(cb) {
	  var server = null;

	  return function requestHandler(req, res) {
	    if (!server) {
	      const config = configProvider.fromWebtaskContext(req.webtaskContext);
	      server = cb(req, config, req.webtaskContext.storage);
	    }

	    return server(req, res);
	  };
	};


/***/ },
/* 37 */
/***/ function(module, exports, __webpack_require__) {

	const jwt = __webpack_require__(27);
	const HookTokenError = __webpack_require__(11).HookTokenError;

	module.exports = function validateHookToken(domain, webtaskUrl, hookPath, extensionSecret, hookToken) {
	  if (!hookToken) {
	    throw new HookTokenError('Hook token missing');
	  }

	  try {
	    jwt.verify(hookToken, extensionSecret, {
	      audience: webtaskUrl + hookPath,
	      issuer: 'https://' + domain
	    });
	    return true;
	  } catch (e) {
	    throw new HookTokenError('Invalid hook token', e);
	  }
	};


/***/ },
/* 38 */
/***/ function(module, exports, __webpack_require__) {

	const url = __webpack_require__(39);

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
/* 39 */
/***/ function(module, exports) {

	module.exports = require("url");

/***/ },
/* 40 */
/***/ function(module, exports, __webpack_require__) {

	module.exports.authenticateUser = __webpack_require__(41);
	module.exports.requireUser = __webpack_require__(44);
	module.exports.errorHandler = __webpack_require__(45);
	module.exports.managementApiClient = __webpack_require__(46);
	module.exports.validateHookToken = __webpack_require__(47);
	module.exports.webtaskConfig = __webpack_require__(48);


/***/ },
/* 41 */
/***/ function(module, exports, __webpack_require__) {

	const jwt = __webpack_require__(42);
	const jwksRsa = __webpack_require__(43);
	const UnauthorizedError = __webpack_require__(10).UnauthorizedError;

	module.exports = function(domain, audience) {
	  return jwt({
	    secret: jwksRsa.expressJwtSecret({
	      cache: true,
	      rateLimit: true,
	      jwksRequestsPerMinute: 5,
	      jwksUri: 'https://' + domain + '/.well-known/jwks.json',
	      handleSigningKeyError: function(err, cb) {
	        if (err instanceof jwksRsa.SigningKeyNotFoundError) {
	          return cb(new UnauthorizedError('A token was provided with an invalid kid'));
	        }

	        return cb(err);
	      }
	    }),

	    // Validate the audience and the issuer.
	    audience: audience,
	    issuer: 'https://' + domain + '/',
	    algorithms: [ 'RS256' ]
	  });
	};


/***/ },
/* 42 */
/***/ function(module, exports) {

	module.exports = require("express-jwt");

/***/ },
/* 43 */
/***/ function(module, exports) {

	module.exports = require("jwks-rsa");

/***/ },
/* 44 */
/***/ function(module, exports, __webpack_require__) {

	const UnauthorizedError = __webpack_require__(10).UnauthorizedError;

	module.exports = function(req, res, next) {
	  if (!req.user) {
	    return next(new UnauthorizedError('Authentication required for this endpoint.'));
	  }

	  return next();
	};


/***/ },
/* 45 */
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
/* 46 */
/***/ function(module, exports, __webpack_require__) {

	const tools = __webpack_require__(10);

	module.exports = function(options) {
	  return function(req, res, next) {
	    const request = req;
	    tools.managementApi.getClient(options)
	      .then(function(auth0) {
	        request.auth0 = auth0;
	        return next();
	      })
	      .catch(function(err) {
	        next(err);
	      });
	  };
	};


/***/ },
/* 47 */
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
/* 48 */
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
/* 49 */
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
/* 50 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var _typeof2 = __webpack_require__(51);

	var _typeof3 = _interopRequireDefault(_typeof2);

	var _stringify = __webpack_require__(119);

	var _stringify2 = _interopRequireDefault(_stringify);

	function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

	var _ = __webpack_require__(21);
	var jwt = __webpack_require__(27);

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
/* 51 */
/***/ function(module, exports, __webpack_require__) {

	"use strict";

	exports.__esModule = true;

	var _iterator = __webpack_require__(52);

	var _iterator2 = _interopRequireDefault(_iterator);

	var _symbol = __webpack_require__(103);

	var _symbol2 = _interopRequireDefault(_symbol);

	var _typeof = typeof _symbol2.default === "function" && typeof _iterator2.default === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof _symbol2.default === "function" && obj.constructor === _symbol2.default && obj !== _symbol2.default.prototype ? "symbol" : typeof obj; };

	function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

	exports.default = typeof _symbol2.default === "function" && _typeof(_iterator2.default) === "symbol" ? function (obj) {
	  return typeof obj === "undefined" ? "undefined" : _typeof(obj);
	} : function (obj) {
	  return obj && typeof _symbol2.default === "function" && obj.constructor === _symbol2.default && obj !== _symbol2.default.prototype ? "symbol" : typeof obj === "undefined" ? "undefined" : _typeof(obj);
	};

/***/ },
/* 52 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = { "default": __webpack_require__(53), __esModule: true };

/***/ },
/* 53 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(54);
	__webpack_require__(98);
	module.exports = __webpack_require__(102).f('iterator');

/***/ },
/* 54 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	var $at  = __webpack_require__(55)(true);

	// 21.1.3.27 String.prototype[@@iterator]()
	__webpack_require__(58)(String, 'String', function(iterated){
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
/* 55 */
/***/ function(module, exports, __webpack_require__) {

	var toInteger = __webpack_require__(56)
	  , defined   = __webpack_require__(57);
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
/* 56 */
/***/ function(module, exports) {

	// 7.1.4 ToInteger
	var ceil  = Math.ceil
	  , floor = Math.floor;
	module.exports = function(it){
	  return isNaN(it = +it) ? 0 : (it > 0 ? floor : ceil)(it);
	};

/***/ },
/* 57 */
/***/ function(module, exports) {

	// 7.2.1 RequireObjectCoercible(argument)
	module.exports = function(it){
	  if(it == undefined)throw TypeError("Can't call method on  " + it);
	  return it;
	};

/***/ },
/* 58 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	var LIBRARY        = __webpack_require__(59)
	  , $export        = __webpack_require__(60)
	  , redefine       = __webpack_require__(75)
	  , hide           = __webpack_require__(65)
	  , has            = __webpack_require__(76)
	  , Iterators      = __webpack_require__(77)
	  , $iterCreate    = __webpack_require__(78)
	  , setToStringTag = __webpack_require__(94)
	  , getPrototypeOf = __webpack_require__(96)
	  , ITERATOR       = __webpack_require__(95)('iterator')
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
/* 59 */
/***/ function(module, exports) {

	module.exports = true;

/***/ },
/* 60 */
/***/ function(module, exports, __webpack_require__) {

	var global    = __webpack_require__(61)
	  , core      = __webpack_require__(62)
	  , ctx       = __webpack_require__(63)
	  , hide      = __webpack_require__(65)
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
/* 61 */
/***/ function(module, exports) {

	// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
	var global = module.exports = typeof window != 'undefined' && window.Math == Math
	  ? window : typeof self != 'undefined' && self.Math == Math ? self : Function('return this')();
	if(typeof __g == 'number')__g = global; // eslint-disable-line no-undef

/***/ },
/* 62 */
/***/ function(module, exports) {

	var core = module.exports = {version: '2.4.0'};
	if(typeof __e == 'number')__e = core; // eslint-disable-line no-undef

/***/ },
/* 63 */
/***/ function(module, exports, __webpack_require__) {

	// optional / simple context binding
	var aFunction = __webpack_require__(64);
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
/* 64 */
/***/ function(module, exports) {

	module.exports = function(it){
	  if(typeof it != 'function')throw TypeError(it + ' is not a function!');
	  return it;
	};

/***/ },
/* 65 */
/***/ function(module, exports, __webpack_require__) {

	var dP         = __webpack_require__(66)
	  , createDesc = __webpack_require__(74);
	module.exports = __webpack_require__(70) ? function(object, key, value){
	  return dP.f(object, key, createDesc(1, value));
	} : function(object, key, value){
	  object[key] = value;
	  return object;
	};

/***/ },
/* 66 */
/***/ function(module, exports, __webpack_require__) {

	var anObject       = __webpack_require__(67)
	  , IE8_DOM_DEFINE = __webpack_require__(69)
	  , toPrimitive    = __webpack_require__(73)
	  , dP             = Object.defineProperty;

	exports.f = __webpack_require__(70) ? Object.defineProperty : function defineProperty(O, P, Attributes){
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
/* 67 */
/***/ function(module, exports, __webpack_require__) {

	var isObject = __webpack_require__(68);
	module.exports = function(it){
	  if(!isObject(it))throw TypeError(it + ' is not an object!');
	  return it;
	};

/***/ },
/* 68 */
/***/ function(module, exports) {

	module.exports = function(it){
	  return typeof it === 'object' ? it !== null : typeof it === 'function';
	};

/***/ },
/* 69 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = !__webpack_require__(70) && !__webpack_require__(71)(function(){
	  return Object.defineProperty(__webpack_require__(72)('div'), 'a', {get: function(){ return 7; }}).a != 7;
	});

/***/ },
/* 70 */
/***/ function(module, exports, __webpack_require__) {

	// Thank's IE8 for his funny defineProperty
	module.exports = !__webpack_require__(71)(function(){
	  return Object.defineProperty({}, 'a', {get: function(){ return 7; }}).a != 7;
	});

/***/ },
/* 71 */
/***/ function(module, exports) {

	module.exports = function(exec){
	  try {
	    return !!exec();
	  } catch(e){
	    return true;
	  }
	};

/***/ },
/* 72 */
/***/ function(module, exports, __webpack_require__) {

	var isObject = __webpack_require__(68)
	  , document = __webpack_require__(61).document
	  // in old IE typeof document.createElement is 'object'
	  , is = isObject(document) && isObject(document.createElement);
	module.exports = function(it){
	  return is ? document.createElement(it) : {};
	};

/***/ },
/* 73 */
/***/ function(module, exports, __webpack_require__) {

	// 7.1.1 ToPrimitive(input [, PreferredType])
	var isObject = __webpack_require__(68);
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
/* 74 */
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
/* 75 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = __webpack_require__(65);

/***/ },
/* 76 */
/***/ function(module, exports) {

	var hasOwnProperty = {}.hasOwnProperty;
	module.exports = function(it, key){
	  return hasOwnProperty.call(it, key);
	};

/***/ },
/* 77 */
/***/ function(module, exports) {

	module.exports = {};

/***/ },
/* 78 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	var create         = __webpack_require__(79)
	  , descriptor     = __webpack_require__(74)
	  , setToStringTag = __webpack_require__(94)
	  , IteratorPrototype = {};

	// 25.1.2.1.1 %IteratorPrototype%[@@iterator]()
	__webpack_require__(65)(IteratorPrototype, __webpack_require__(95)('iterator'), function(){ return this; });

	module.exports = function(Constructor, NAME, next){
	  Constructor.prototype = create(IteratorPrototype, {next: descriptor(1, next)});
	  setToStringTag(Constructor, NAME + ' Iterator');
	};

/***/ },
/* 79 */
/***/ function(module, exports, __webpack_require__) {

	// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
	var anObject    = __webpack_require__(67)
	  , dPs         = __webpack_require__(80)
	  , enumBugKeys = __webpack_require__(92)
	  , IE_PROTO    = __webpack_require__(89)('IE_PROTO')
	  , Empty       = function(){ /* empty */ }
	  , PROTOTYPE   = 'prototype';

	// Create object with fake `null` prototype: use iframe Object with cleared prototype
	var createDict = function(){
	  // Thrash, waste and sodomy: IE GC bug
	  var iframe = __webpack_require__(72)('iframe')
	    , i      = enumBugKeys.length
	    , lt     = '<'
	    , gt     = '>'
	    , iframeDocument;
	  iframe.style.display = 'none';
	  __webpack_require__(93).appendChild(iframe);
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
/* 80 */
/***/ function(module, exports, __webpack_require__) {

	var dP       = __webpack_require__(66)
	  , anObject = __webpack_require__(67)
	  , getKeys  = __webpack_require__(81);

	module.exports = __webpack_require__(70) ? Object.defineProperties : function defineProperties(O, Properties){
	  anObject(O);
	  var keys   = getKeys(Properties)
	    , length = keys.length
	    , i = 0
	    , P;
	  while(length > i)dP.f(O, P = keys[i++], Properties[P]);
	  return O;
	};

/***/ },
/* 81 */
/***/ function(module, exports, __webpack_require__) {

	// 19.1.2.14 / 15.2.3.14 Object.keys(O)
	var $keys       = __webpack_require__(82)
	  , enumBugKeys = __webpack_require__(92);

	module.exports = Object.keys || function keys(O){
	  return $keys(O, enumBugKeys);
	};

/***/ },
/* 82 */
/***/ function(module, exports, __webpack_require__) {

	var has          = __webpack_require__(76)
	  , toIObject    = __webpack_require__(83)
	  , arrayIndexOf = __webpack_require__(86)(false)
	  , IE_PROTO     = __webpack_require__(89)('IE_PROTO');

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
/* 83 */
/***/ function(module, exports, __webpack_require__) {

	// to indexed object, toObject with fallback for non-array-like ES3 strings
	var IObject = __webpack_require__(84)
	  , defined = __webpack_require__(57);
	module.exports = function(it){
	  return IObject(defined(it));
	};

/***/ },
/* 84 */
/***/ function(module, exports, __webpack_require__) {

	// fallback for non-array-like ES3 and non-enumerable old V8 strings
	var cof = __webpack_require__(85);
	module.exports = Object('z').propertyIsEnumerable(0) ? Object : function(it){
	  return cof(it) == 'String' ? it.split('') : Object(it);
	};

/***/ },
/* 85 */
/***/ function(module, exports) {

	var toString = {}.toString;

	module.exports = function(it){
	  return toString.call(it).slice(8, -1);
	};

/***/ },
/* 86 */
/***/ function(module, exports, __webpack_require__) {

	// false -> Array#indexOf
	// true  -> Array#includes
	var toIObject = __webpack_require__(83)
	  , toLength  = __webpack_require__(87)
	  , toIndex   = __webpack_require__(88);
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
/* 87 */
/***/ function(module, exports, __webpack_require__) {

	// 7.1.15 ToLength
	var toInteger = __webpack_require__(56)
	  , min       = Math.min;
	module.exports = function(it){
	  return it > 0 ? min(toInteger(it), 0x1fffffffffffff) : 0; // pow(2, 53) - 1 == 9007199254740991
	};

/***/ },
/* 88 */
/***/ function(module, exports, __webpack_require__) {

	var toInteger = __webpack_require__(56)
	  , max       = Math.max
	  , min       = Math.min;
	module.exports = function(index, length){
	  index = toInteger(index);
	  return index < 0 ? max(index + length, 0) : min(index, length);
	};

/***/ },
/* 89 */
/***/ function(module, exports, __webpack_require__) {

	var shared = __webpack_require__(90)('keys')
	  , uid    = __webpack_require__(91);
	module.exports = function(key){
	  return shared[key] || (shared[key] = uid(key));
	};

/***/ },
/* 90 */
/***/ function(module, exports, __webpack_require__) {

	var global = __webpack_require__(61)
	  , SHARED = '__core-js_shared__'
	  , store  = global[SHARED] || (global[SHARED] = {});
	module.exports = function(key){
	  return store[key] || (store[key] = {});
	};

/***/ },
/* 91 */
/***/ function(module, exports) {

	var id = 0
	  , px = Math.random();
	module.exports = function(key){
	  return 'Symbol('.concat(key === undefined ? '' : key, ')_', (++id + px).toString(36));
	};

/***/ },
/* 92 */
/***/ function(module, exports) {

	// IE 8- don't enum bug keys
	module.exports = (
	  'constructor,hasOwnProperty,isPrototypeOf,propertyIsEnumerable,toLocaleString,toString,valueOf'
	).split(',');

/***/ },
/* 93 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = __webpack_require__(61).document && document.documentElement;

/***/ },
/* 94 */
/***/ function(module, exports, __webpack_require__) {

	var def = __webpack_require__(66).f
	  , has = __webpack_require__(76)
	  , TAG = __webpack_require__(95)('toStringTag');

	module.exports = function(it, tag, stat){
	  if(it && !has(it = stat ? it : it.prototype, TAG))def(it, TAG, {configurable: true, value: tag});
	};

/***/ },
/* 95 */
/***/ function(module, exports, __webpack_require__) {

	var store      = __webpack_require__(90)('wks')
	  , uid        = __webpack_require__(91)
	  , Symbol     = __webpack_require__(61).Symbol
	  , USE_SYMBOL = typeof Symbol == 'function';

	var $exports = module.exports = function(name){
	  return store[name] || (store[name] =
	    USE_SYMBOL && Symbol[name] || (USE_SYMBOL ? Symbol : uid)('Symbol.' + name));
	};

	$exports.store = store;

/***/ },
/* 96 */
/***/ function(module, exports, __webpack_require__) {

	// 19.1.2.9 / 15.2.3.2 Object.getPrototypeOf(O)
	var has         = __webpack_require__(76)
	  , toObject    = __webpack_require__(97)
	  , IE_PROTO    = __webpack_require__(89)('IE_PROTO')
	  , ObjectProto = Object.prototype;

	module.exports = Object.getPrototypeOf || function(O){
	  O = toObject(O);
	  if(has(O, IE_PROTO))return O[IE_PROTO];
	  if(typeof O.constructor == 'function' && O instanceof O.constructor){
	    return O.constructor.prototype;
	  } return O instanceof Object ? ObjectProto : null;
	};

/***/ },
/* 97 */
/***/ function(module, exports, __webpack_require__) {

	// 7.1.13 ToObject(argument)
	var defined = __webpack_require__(57);
	module.exports = function(it){
	  return Object(defined(it));
	};

/***/ },
/* 98 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(99);
	var global        = __webpack_require__(61)
	  , hide          = __webpack_require__(65)
	  , Iterators     = __webpack_require__(77)
	  , TO_STRING_TAG = __webpack_require__(95)('toStringTag');

	for(var collections = ['NodeList', 'DOMTokenList', 'MediaList', 'StyleSheetList', 'CSSRuleList'], i = 0; i < 5; i++){
	  var NAME       = collections[i]
	    , Collection = global[NAME]
	    , proto      = Collection && Collection.prototype;
	  if(proto && !proto[TO_STRING_TAG])hide(proto, TO_STRING_TAG, NAME);
	  Iterators[NAME] = Iterators.Array;
	}

/***/ },
/* 99 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	var addToUnscopables = __webpack_require__(100)
	  , step             = __webpack_require__(101)
	  , Iterators        = __webpack_require__(77)
	  , toIObject        = __webpack_require__(83);

	// 22.1.3.4 Array.prototype.entries()
	// 22.1.3.13 Array.prototype.keys()
	// 22.1.3.29 Array.prototype.values()
	// 22.1.3.30 Array.prototype[@@iterator]()
	module.exports = __webpack_require__(58)(Array, 'Array', function(iterated, kind){
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
/* 100 */
/***/ function(module, exports) {

	module.exports = function(){ /* empty */ };

/***/ },
/* 101 */
/***/ function(module, exports) {

	module.exports = function(done, value){
	  return {value: value, done: !!done};
	};

/***/ },
/* 102 */
/***/ function(module, exports, __webpack_require__) {

	exports.f = __webpack_require__(95);

/***/ },
/* 103 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = { "default": __webpack_require__(104), __esModule: true };

/***/ },
/* 104 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(105);
	__webpack_require__(116);
	__webpack_require__(117);
	__webpack_require__(118);
	module.exports = __webpack_require__(62).Symbol;

/***/ },
/* 105 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';
	// ECMAScript 6 symbols shim
	var global         = __webpack_require__(61)
	  , has            = __webpack_require__(76)
	  , DESCRIPTORS    = __webpack_require__(70)
	  , $export        = __webpack_require__(60)
	  , redefine       = __webpack_require__(75)
	  , META           = __webpack_require__(106).KEY
	  , $fails         = __webpack_require__(71)
	  , shared         = __webpack_require__(90)
	  , setToStringTag = __webpack_require__(94)
	  , uid            = __webpack_require__(91)
	  , wks            = __webpack_require__(95)
	  , wksExt         = __webpack_require__(102)
	  , wksDefine      = __webpack_require__(107)
	  , keyOf          = __webpack_require__(108)
	  , enumKeys       = __webpack_require__(109)
	  , isArray        = __webpack_require__(112)
	  , anObject       = __webpack_require__(67)
	  , toIObject      = __webpack_require__(83)
	  , toPrimitive    = __webpack_require__(73)
	  , createDesc     = __webpack_require__(74)
	  , _create        = __webpack_require__(79)
	  , gOPNExt        = __webpack_require__(113)
	  , $GOPD          = __webpack_require__(115)
	  , $DP            = __webpack_require__(66)
	  , $keys          = __webpack_require__(81)
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
	  __webpack_require__(114).f = gOPNExt.f = $getOwnPropertyNames;
	  __webpack_require__(111).f  = $propertyIsEnumerable;
	  __webpack_require__(110).f = $getOwnPropertySymbols;

	  if(DESCRIPTORS && !__webpack_require__(59)){
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
	$Symbol[PROTOTYPE][TO_PRIMITIVE] || __webpack_require__(65)($Symbol[PROTOTYPE], TO_PRIMITIVE, $Symbol[PROTOTYPE].valueOf);
	// 19.4.3.5 Symbol.prototype[@@toStringTag]
	setToStringTag($Symbol, 'Symbol');
	// 20.2.1.9 Math[@@toStringTag]
	setToStringTag(Math, 'Math', true);
	// 24.3.3 JSON[@@toStringTag]
	setToStringTag(global.JSON, 'JSON', true);

/***/ },
/* 106 */
/***/ function(module, exports, __webpack_require__) {

	var META     = __webpack_require__(91)('meta')
	  , isObject = __webpack_require__(68)
	  , has      = __webpack_require__(76)
	  , setDesc  = __webpack_require__(66).f
	  , id       = 0;
	var isExtensible = Object.isExtensible || function(){
	  return true;
	};
	var FREEZE = !__webpack_require__(71)(function(){
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
/* 107 */
/***/ function(module, exports, __webpack_require__) {

	var global         = __webpack_require__(61)
	  , core           = __webpack_require__(62)
	  , LIBRARY        = __webpack_require__(59)
	  , wksExt         = __webpack_require__(102)
	  , defineProperty = __webpack_require__(66).f;
	module.exports = function(name){
	  var $Symbol = core.Symbol || (core.Symbol = LIBRARY ? {} : global.Symbol || {});
	  if(name.charAt(0) != '_' && !(name in $Symbol))defineProperty($Symbol, name, {value: wksExt.f(name)});
	};

/***/ },
/* 108 */
/***/ function(module, exports, __webpack_require__) {

	var getKeys   = __webpack_require__(81)
	  , toIObject = __webpack_require__(83);
	module.exports = function(object, el){
	  var O      = toIObject(object)
	    , keys   = getKeys(O)
	    , length = keys.length
	    , index  = 0
	    , key;
	  while(length > index)if(O[key = keys[index++]] === el)return key;
	};

/***/ },
/* 109 */
/***/ function(module, exports, __webpack_require__) {

	// all enumerable object keys, includes symbols
	var getKeys = __webpack_require__(81)
	  , gOPS    = __webpack_require__(110)
	  , pIE     = __webpack_require__(111);
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
/* 110 */
/***/ function(module, exports) {

	exports.f = Object.getOwnPropertySymbols;

/***/ },
/* 111 */
/***/ function(module, exports) {

	exports.f = {}.propertyIsEnumerable;

/***/ },
/* 112 */
/***/ function(module, exports, __webpack_require__) {

	// 7.2.2 IsArray(argument)
	var cof = __webpack_require__(85);
	module.exports = Array.isArray || function isArray(arg){
	  return cof(arg) == 'Array';
	};

/***/ },
/* 113 */
/***/ function(module, exports, __webpack_require__) {

	// fallback for IE11 buggy Object.getOwnPropertyNames with iframe and window
	var toIObject = __webpack_require__(83)
	  , gOPN      = __webpack_require__(114).f
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
/* 114 */
/***/ function(module, exports, __webpack_require__) {

	// 19.1.2.7 / 15.2.3.4 Object.getOwnPropertyNames(O)
	var $keys      = __webpack_require__(82)
	  , hiddenKeys = __webpack_require__(92).concat('length', 'prototype');

	exports.f = Object.getOwnPropertyNames || function getOwnPropertyNames(O){
	  return $keys(O, hiddenKeys);
	};

/***/ },
/* 115 */
/***/ function(module, exports, __webpack_require__) {

	var pIE            = __webpack_require__(111)
	  , createDesc     = __webpack_require__(74)
	  , toIObject      = __webpack_require__(83)
	  , toPrimitive    = __webpack_require__(73)
	  , has            = __webpack_require__(76)
	  , IE8_DOM_DEFINE = __webpack_require__(69)
	  , gOPD           = Object.getOwnPropertyDescriptor;

	exports.f = __webpack_require__(70) ? gOPD : function getOwnPropertyDescriptor(O, P){
	  O = toIObject(O);
	  P = toPrimitive(P, true);
	  if(IE8_DOM_DEFINE)try {
	    return gOPD(O, P);
	  } catch(e){ /* empty */ }
	  if(has(O, P))return createDesc(!pIE.f.call(O, P), O[P]);
	};

/***/ },
/* 116 */
/***/ function(module, exports) {

	

/***/ },
/* 117 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(107)('asyncIterator');

/***/ },
/* 118 */
/***/ function(module, exports, __webpack_require__) {

	__webpack_require__(107)('observable');

/***/ },
/* 119 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = { "default": __webpack_require__(120), __esModule: true };

/***/ },
/* 120 */
/***/ function(module, exports, __webpack_require__) {

	var core  = __webpack_require__(62)
	  , $JSON = core.JSON || (core.JSON = {stringify: JSON.stringify});
	module.exports = function stringify(it){ // eslint-disable-line no-unused-vars
	  return $JSON.stringify.apply($JSON, arguments);
	};

/***/ },
/* 121 */
/***/ function(module, exports) {

	"use strict";

	module.exports = "<html lang=\"en\">\n<head>\n  <title>Auth0 - Protocol Debugger</title>\n  <meta charset=\"UTF-8\">\n  <meta http-equiv=\"X-UA-Compatible\" content=\"IE=Edge\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n  <link rel=\"shortcut icon\" href=\"https://cdn.auth0.com/styleguide/4.6.13/lib/logos/img/favicon.png\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"https://cdn.auth0.com/styles/zocial.min.css\">\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"https://cdn.auth0.com/manage/v0.3.1715/css/index.min.css\">\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"https://cdn.auth0.com/styleguide/4.6.13/index.css\">\n  <link rel=\"stylesheet\" href=\"//cdnjs.cloudflare.com/ajax/libs/highlight.js/9.7.0/styles/github.min.css\">\n  <script src=\"//cdnjs.cloudflare.com/ajax/libs/highlight.js/9.7.0/highlight.min.js\"></script>\n  <style type=\"text/css\">\n    p.controls-info {\n      font-size: 13px;\n      color: #000;\n      opacity: .56;\n      line-height: 18px;\n      margin: 8px 0 0 0;\n      clear: both;\n    }\n    code.xml {\n      color: black !important;\n      background-color: #fbfbfb !important;\n      margin-top: -25px !important;\n      margin-bottom: -51px !important;\n    }\n    pre.json-object {\n      background-color: #fbfbfb;\n      border: 1px solid #f1f1f1;\n      border-radius: 0px;\n      padding: 10px 10px;\n      font-size: 12px;\n    }\n    .json-object .json-key {\n      color: #16214D;\n    }\n    .json-object .json-value {\n      color: #01B48F;\n    }\n    .json-object .json-string {\n      color: #EB5424;\n    }\n  </style>\n</head>\n<body>\n<div id=\"app\">\n  <div>\n    <header class=\"dashboard-header\">\n      <nav role=\"navigation\" class=\"navbar navbar-default\">\n        <div class=\"container\">\n          <div class=\"navbar-header\">\n            <h1 class=\"navbar-brand\" style=\"padding-top: 0px;\"><a href=\"https://manage.auth0.com\"><span>Auth0</span></a></h1>\n          </div>\n          <div id=\"navbar-collapse\" class=\"collapse navbar-collapse\">\n            <ul class=\"nav navbar-nav navbar-right\">\n              <li><a target=\"_blank\" href=\"https://auth0.com/support\">Help &amp; Support</a></li>\n              <li><a target=\"_blank\" href=\"https://auth0.com/docs\">Documentation</a></li>\n            </ul>\n          </div>\n        </div>\n      </nav>\n    </header>\n    <div class=\"container\">\n      <div class=\"row\">\n        <div class=\"col-xs-12\">\n          <div class=\"row\">\n            <div class=\"col-xs-12\">\n              <h1 class=\"pull-left\" style=\"padding-top: 10px;\">Protocol Debugger</h1>\n            </div>\n          </div>\n          <div class=\"row\">\n            <div class=\"col-xs-12\">\n            \t<div class=\"widget-title title-with-nav-bars\">\n            \t\t<ul id=\"tabs\" class=\"nav nav-tabs\">\n            \t\t\t<li class=\"active\"><a data-toggle=\"tab\" href=\"#login\"><span class=\"tab-title\">Login</span></a></li>\n              \t\t<li><a data-toggle=\"tab\" href=\"#request\"><span class=\"tab-title\">Request</span></a></li>\n            \t\t</ul>\n            \t</div>\n            \t<div id=\"content-area\" class=\"tab-content\">\n                <div id=\"login\" class=\"tab-pane active\">\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div class=\"alert alert-warning\">Rendering (including of hash fragment, client credentials ...) happens on the server, which means that in some cases your tokens might be sent to the webtask hosting this page. You can find the implementation <a href=\"https://github.com/sandrinodimattia/auth-protocol-debugger\">on GitHub</a>.</div>\n                    </div>\n                    <div class=\"col-xs-12\">\n                      <button id=\"reset_settings\" class=\"btn btn-success\">Clear Settings</button>\n                      <p class=\"controls-info\">Hit this button if you want to remove everything from local storage.</p>\n                    </div>\n                    <div class=\"col-xs-12\" style=\"margin-top: 25px\">\n                      <div>\n                        <div class=\"widget-title title-with-nav-bars\">\n                      \t\t<ul id=\"login-tabs\" class=\"nav nav-tabs\">\n                      \t\t\t<li class=\"active\"><a data-toggle=\"tab\" href=\"#configuration\"><span class=\"tab-title\">Configuration</span></a></li>\n                        \t\t<li><a data-toggle=\"tab\" href=\"#oauth2\"><span class=\"tab-title\">OAuth2 / OIDC</span></a></li>\n                        \t\t<li><a data-toggle=\"tab\" href=\"#other-flows\"><span class=\"tab-title\">Other Flows</span></a></li>\n                      \t\t</ul>\n                      \t</div>\n                      \t<div id=\"login-content-area\" class=\"tab-content\">\n                          <div id=\"configuration\" class=\"tab-pane active\">\n                            <p>Enter your account settings and additional application settings here (these will be persisted in localstorage).</p>\n                            <form class=\"form-horizontal col-xs-12\">\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Domain</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"domain\" type=\"text\" class=\"form-control\" value=\"you.auth0.com\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Client ID</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"client_id\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Client Secret</label>\n                                <div class=\"col-xs-6\">\n                                  <input id=\"client_secret\" type=\"password\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Optional: Not all clients have a secret (eg: Mobile, SPA, Public). Don't store any production secrets here.</p>\n                                </div>\n                                <div class=\"col-xs-4\">\n                                  <div class=\"ui-switch ui-switch-labeled ui-switch-xl\">\n                                    <input id=\"save_client_secret\" type=\"checkbox\" />\n                                    <label data-label-true=\"Save in Local Storage\" data-label-false=\"Don't Save in Local Storage\" class=\"status\"></label>\n                                  </div>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Callback URL</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"callback_url\" readonly type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Make sure you configure this as the Callback Url on your client.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">SSO</label>\n                                <div class=\"col-xs-3\">\n                                  <div class=\"ui-switch\">\n                                    <input id=\"use_sso\" type=\"checkbox\"/>\n                                    <label class=\"status\"></label>\n                                  </div>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">State</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"state\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">This might translate to RelayState or wctx depending on the protocol.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Connection</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"connection\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Sprecify the name of a connection to skip the login page (eg: <strong>google-oauth2</strong>).</p>\n                                </div>\n                              </div>\n                            </form>\n                          </div>\n                          <div id=\"oauth2\" class=\"tab-pane\">\n                            <div class=\"alert alert-info\">Specification: <a href=\"https://tools.ietf.org/html/rfc6749#section-1.3.3\">OAuth2</a></div>\n                            <h5>User Flows</h5>\n                            <button id=\"oidc_oauth2\" class=\"btn btn-primary\">OAuth2 / OIDC Login</button>\n                            <button id=\"oauth2_code_exchange\" class=\"btn btn-primary\">OAuth2 Code Exchange</button>\n                            <button id=\"oauth2_refresh_token_exchange\" class=\"btn btn-primary\">OAuth2 Refresh Token Exchange</button>\n                            <p class=\"controls-info\">The exchanges will use the Client ID (and optionally Secret) from the Configuration tab.</p>\n                            <h5>Machine to Machine</h5>\n                            <button id=\"oauth2_client_credentials\" class=\"btn btn-primary\">OAuth2 Client Credentials</button>\n                            <p class=\"controls-info\">This will use the Client ID and Secret from the Configuration tab.</p>\n                            <h5>Resource Owner Password Credentials</h5>\n                            <form class=\"form-horizontal col-xs-12\">\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Username</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"username\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Password</label>\n                                <div class=\"col-xs-6\">\n                                  <input id=\"password\" type=\"password\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Optional: Only store passwords for test accounts here.</p>\n                                </div>\n                                <div class=\"col-xs-4\">\n                                  <div class=\"ui-switch ui-switch-labeled ui-switch-xl\">\n                                    <input id=\"save_password\" type=\"checkbox\" />\n                                    <label data-label-true=\"Save in Local Storage\" data-label-false=\"Don't Save in Local Storage\" class=\"status\"></label>\n                                  </div>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Device</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"device\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">This field is here for legacy purposes. It's not part of the spec.</p>\n                                </div>\n                              </div>\n                            </form>\n                            <button id=\"oauth2_password_grant\" class=\"btn btn-primary\">Password Grant</button>\n                            <button id=\"oauth2_ro\" class=\"btn btn-primary\">Resource Owner Endpoint</button>\n                            <p class=\"controls-info\">The Resource Owner Endpoint is here for legacy purposes. It's not part of the spec.</p>\n                            <h5>Delegation</h5>\n                            <p class=\"controls-info\">Not part of the spec - this is here for legacy purposes only.</p>\n                            <form class=\"form-horizontal col-xs-12\">\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">ID Token</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"delegation_id_token\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Refresh Token</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"delegation_refresh_token\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Target Client ID</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"delegation_target\" type=\"text\" class=\"form-control\" value=\"\">\n                                </div>\n                              </div>\n                            </form>\n                            <button id=\"oauth2_delegation\" class=\"btn btn-primary\">Delegation</button>\n                            <h5>Settings</h5>\n                            <p>The following settings might behave differently if you're using OAuth2 as a Service (Preview)</p>\n                            <form class=\"form-horizontal col-xs-12\">\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">PKCE</label>\n                                <div class=\"col-xs-10\">\n                                  <div class=\"ui-switch\">\n                                    <input id=\"use_pkce\" type=\"checkbox\"/>\n                                    <label class=\"status\"></label>\n                                  </div>\n                                  <p class=\"controls-info\">The PKCE (Proof Key for Code Exchange by OAuth Public Clients) or Hybrid Flow is a better alternative to the implicit flow for Mobile Apps. In Auth0, make sure you set the client type to \"Native\".</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Audience</label>\n                                <div class=\"col-xs-7\">\n                                  <input id=\"audience\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">Only required when you need an access token.</p>\n                                </div>\n                                <div class=\"col-xs-3\">\n                                  <div class=\"ui-switch ui-switch-labeled ui-switch-md\">\n                                    <input id=\"use_audience\" type=\"checkbox\" />\n                                    <label data-label-true=\"Save in Local Storage\" data-label-false=\"Use Audience\" class=\"status\"></label>\n                                  </div>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Authorization Code</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"authorization_code\" type=\"text\" class=\"form-control\" value=\"{{authorization_code}}\">\n                                  <p class=\"controls-info\">Set the response type to <strong>code</strong> and then press the <strong>OIDC / OAuth2</strong> button to get an authorization code.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Code Verifier</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"code_verifier\" type=\"text\" class=\"form-control\" value=\"{{code_verifier}}\">\n                                  <p class=\"controls-info\">If you're using <strong>PKCE</strong>, this is what will be used instead of the Client Secret.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Refresh Token</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"refresh_token\" type=\"text\" class=\"form-control\" value=\"{{refresh_token}}\">\n                                  <p class=\"controls-info\">Set the response type to <strong>code</strong>, request the <strong>offline_access</strong> scope and then press the <strong>OIDC / OAuth2</strong> button to get an authorization code.</p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Response Type</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"response_type\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">You can try a mix of <strong>code</strong>, <strong>id_token</strong>, <strong>token</strong></p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\">\n                                <label class=\"col-xs-2 control-label\">Response Mode</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"response_mode\" type=\"text\" class=\"form-control\" value=\"\">\n                                  <p class=\"controls-info\">You can try something like <strong>fragment</strong>, <strong>query</strong> or <strong>form_post</strong></p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Scope</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"scope\" type=\"text\" class=\"form-control\" value=\"openid name email\">\n                                  <p class=\"controls-info\">You can try something like <strong>openid name email read:appointments</strong></p>\n                                </div>\n                              </div>\n                              <div class=\"form-group\"><label class=\"col-xs-2 control-label\">Prompt</label>\n                                <div class=\"col-xs-10\">\n                                  <input id=\"prompt\" type=\"text\" class=\"form-control\" value=\"openid name email\">\n                                  <p class=\"controls-info\">You can try something like <strong>consent</strong> or <strong>login</strong></p>\n                                </div>\n                              </div>\n                            </form>\n                          </div>\n                          <div id=\"other-flows\" class=\"tab-pane\">\n                            <button id=\"saml\" class=\"btn btn-primary\">SAML</button>\n                            <button id=\"wsfed\" class=\"btn btn-primary\">WS-Federation</button>\n                            <h5>Logout</h5>\n                            <button id=\"logout\" class=\"btn btn-primary\">Logout</button>\n                            <button id=\"logout-federated\" class=\"btn btn-primary\">Logout (Federated)</button>\n                            <h5>SSO</h5>\n                            <button id=\"sso-data\" class=\"btn btn-primary\">Get SSO Data</button>\n                            <div id=\"sso-data-output\"></div>\n                          </div>\n                        </div>\n                      </div>\n                    </div>\n                  </div>\n                </div>\n            \t\t<div id=\"request\" class=\"tab-pane\">\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Details</h5>\n                        <form class=\"form-horizontal col-xs-12\">\n                          <div class=\"form-group\"><label class=\"col-xs-1 control-label\">Method</label>\n                            <div class=\"col-xs-11\"><input type=\"text\" readonly=\"\" class=\"form-control\" value=\"{{method}}\"></div>\n                          </div>\n                          <div class=\"form-group\"><label class=\"col-xs-1 control-label\">Url</label>\n                            <div class=\"col-xs-11\"><input type=\"text\" readonly=\"\" class=\"form-control\" value=\"{{baseUrl}}\"></div>\n                          </div>\n                        </form>\n                      </div>\n                    </div>\n                  </div>\n                  {{#if body}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Body</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{body}}}</pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  {{#if id_token}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>ID Token</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{id_token}}}</pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  {{#if access_token}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Access Token</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{access_token}}}</pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  <div id=\"hash_fragment\"></div>\n                  {{#if samlResponse}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>SAML Response</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre>\n                        <code class=\"xml\">{{{samlResponse}}}</code>\n                      </pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  {{#if wsFedResult}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>WS-Federation Result</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre>\n                        <code class=\"xml\">{{{wsFedResult}}}</code>\n                      </pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  {{#if query}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Query</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{query}}}</pre>\n                    </div>\n                  </div>\n                  {{/if}}\n                  <div class=\"row\">\n                    <div class=\"col-xs-12\">\n                      <div>\n                        <h5>Headers</h5>\n                      </div>\n                    </div>\n                    <div class=\"col-lg-12\">\n                      <pre class=\"json-object\">{{{headers}}}</pre>\n                    </div>\n                  </div>\n            \t\t</div>\n            \t\t<div id=\"login\" class=\"tab-pane\">\n            \t\t</div>\n            \t</div>\n            </div>\n          </div>\n        </div>\n      </div>\n    </div>\n  </div>\n  <div id=\"modal-dialog\" tabindex=\"-1\" role=\"dialog\" aria-hidden=\"true\" class=\"modal\">\n    <div class=\"modal-dialog\">\n      <div class=\"modal-content\">\n        <div class=\"modal-header has-border\">\n          <button type=\"button\" data-dismiss=\"modal\" class=\"close\"><span aria-hidden=\"true\">\xD7</span><span class=\"sr-only\">Close</span></button>\n          <h4 id=\"modal-title\" class=\"modal-title\"></h4>\n        </div>\n        <div id=\"modal-body\" class=\"modal-body\"></div>\n        <div class=\"modal-footer\">\n          <button data-dismiss=\"modal\" id=\"close-modal\" type=\"button\" class=\"btn btn-primary\">Close</button>\n        </div>\n      </div>\n    </div>\n  </div>\n</div>\n<script src=\"//cdnjs.cloudflare.com/ajax/libs/jquery/1.11.3/jquery.js\"></script>\n<script src=\"//cdn.auth0.com/w2/auth0-6.js\"></script>\n<script type=\"text/javascript\" src=\"//cdn.auth0.com/manage/v0.3.1715/js/bundle.js\"></script>\n<script>hljs.initHighlightingOnLoad();</script>\n<script type=\"text/javascript\">\nfunction read() {\n  $('#audience').val(localStorage.getItem('auth_debugger_audience'));\n  $('#callback_url').val(window.location.protocol + \"//\" + window.location.hostname + (window.location.port ? ':' + window.location.port : '') + window.location.pathname);\n  $('#client_id').val(localStorage.getItem('auth_debugger_client_id') || 'IsTxQ7jAYAXL5r5HM4L1RMzsSG0UHeOy');\n  $('#client_secret').val(localStorage.getItem('auth_debugger_client_secret'));\n  $('#code_verifier').val(localStorage.getItem('auth_debugger_code_verifier'));\n  $('#connection').val(localStorage.getItem('auth_debugger_connection'));\n  $('#device').val(localStorage.getItem('auth_debugger_device'));\n  $('#domain').val(localStorage.getItem('auth_debugger_domain') || 'sandrino.auth0.com');\n  $('#password').val(localStorage.getItem('auth_debugger_password'));\n  $('#delegation_target').val(localStorage.getItem('auth_debugger_delegation_target'));\n  $('#prompt').val(localStorage.getItem('auth_debugger_prompt') || '');\n  $('#refresh_token').val(localStorage.getItem('auth_debugger_refresh_token'));\n  $('#response_mode').val(localStorage.getItem('auth_debugger_response_mode') || '');\n  $('#response_type').val(localStorage.getItem('auth_debugger_response_type') || 'token');\n  $('#save_client_secret').prop('checked', localStorage.getItem('auth_debugger_client_secret') && localStorage.getItem('auth_debugger_client_secret').length);\n  $('#save_password').prop('checked', localStorage.getItem('auth_debugger_password') && localStorage.getItem('auth_debugger_password').length);\n  $('#scope').val(localStorage.getItem('auth_debugger_scope') || 'openid name email nickname');\n  $('#state').val(localStorage.getItem('auth_debugger_state') || 'my-custom-state');\n  $('#username').val(localStorage.getItem('auth_debugger_username'));\n  if (localStorage.getItem('auth_debugger_use_audience') === \"1\") {\n    $('#use_audience').prop('checked', 'checked');\n  }\n  if (localStorage.getItem('auth_debugger_use_pkce') === \"1\") {\n    $('#use_pkce').prop('checked', 'checked');\n  }\n  if (localStorage.getItem('auth_debugger_use_sso') === \"1\") {\n    $('#use_sso').prop('checked', 'checked');\n  }\n}\nfunction save() {\n  localStorage.setItem('auth_debugger_audience', $('#audience').val());\n  localStorage.setItem('auth_debugger_client_id', $('#client_id').val());\n  localStorage.setItem('auth_debugger_client_secret', $('#save_client_secret').is(':checked') ? $('#client_secret').val() : '');\n  localStorage.setItem('auth_debugger_code_verifier', $('#code_verifier').val());\n  localStorage.setItem('auth_debugger_connection', $('#connection').val());\n  localStorage.setItem('auth_debugger_domain', $('#domain').val());\n  localStorage.setItem('auth_debugger_delegation_target', $('#delegation_target').val());\n  localStorage.setItem('auth_debugger_device', $('#device').val());\n  localStorage.setItem('auth_debugger_password', $('#save_password').is(':checked') ? $('#save_password').val() : '');\n  localStorage.setItem('auth_debugger_prompt', $('#prompt').val());\n  localStorage.setItem('auth_debugger_refresh_token', $('#refresh_token').val());\n  localStorage.setItem('auth_debugger_response_mode', $('#response_mode').val());\n  localStorage.setItem('auth_debugger_response_type', $('#response_type').val());\n  localStorage.setItem('auth_debugger_scope', $('#scope').val());\n  localStorage.setItem('auth_debugger_state', $('#state').val());\n  localStorage.setItem('auth_debugger_use_audience', $('#use_audience').is(':checked') ? \"1\" : \"0\");\n  localStorage.setItem('auth_debugger_use_pkce', $('#use_pkce').is(':checked') ? \"1\" : \"0\");\n  localStorage.setItem('auth_debugger_use_sso', $('#use_sso').is(':checked') ? \"1\" : \"0\");\n  localStorage.setItem('auth_debugger_username', $('#username').val());\n}\nfunction executeRequest(title, url, opt) {\n  save();\n  $('#modal-title').html(title);\n  $('#modal-body').html('Loading...');\n  $('#modal-dialog').modal({ show: true });\n  $.post(url, opt)\n    .done(function(data) {\n      data.request = opt;\n      if (data.refresh_token) {\n        localStorage.setItem('auth_debugger_refresh_token', data.refresh_token);\n      }\n      if (data.request.password) {\n        data.request.password = '*****************';\n      }\n      if (data.request.client_secret) {\n        data.request.client_secret = '*****************';\n      }\n      $.ajax({ type: \"POST\", url: '{{baseUrl}}/request', data: JSON.stringify(data), contentType: 'application/json' })\n        .done(function(data) {\n          $('#modal-body').html(data);\n          $('#modal-body').prepend($('<pre/>', { 'class':'json-object', 'html': 'POST ' + url }));\n        })\n        .fail(function(err) {\n          $('#modal-body').html('<p>Error decoding the response.</p>');\n          $('<pre/>', { 'class':'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#modal-body');\n        });\n    })\n    .fail(function(err) {\n      if (opt.password) {\n        opt.password = '*****************';\n      }\n      if (opt.client_secret) {\n        opt.client_secret = '*****************';\n      }\n      $.ajax({ type: \"POST\", url: '{{baseUrl}}/request', data: JSON.stringify({ request: opt, err: err }), contentType: 'application/json' })\n        .done(function(data) {\n          $('#modal-body').html(data);\n          $('#modal-body').prepend($('<pre/>', { 'class':'json-object', 'html': 'POST ' + url }));\n        })\n        .fail(function(err) {\n          $('#modal-body').html('<p>Error decoding the response.</p>');\n          $('<pre/>', { 'class':'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#modal-body');\n        });\n    });\n}\nif (!window.location.origin) {\n  window.location.origin = window.location.protocol + \"//\" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');\n}\nvar callbackUrl = window.location.origin + window.location.pathname;\n$(function () {\n  read();\n  if (\"{{method}}\" === 'POST' || (window.location.hash && window.location.hash.length > 1) || (window.location.search && window.location.search.length > 1 && window.location.search !== '?webtask_no_cache=1')) {\n    $('#tabs a[href=\"#request\"]').tab('show');\n  }\n  if (window.location.hash && window.location.hash.length > 1) {\n    $('#hash_fragment').load(window.location.origin + window.location.pathname + '/hash?' + window.location.hash.replace(/^#/,\"\"));\n  }\n  $('#saml').click(function(e) {\n    e.preventDefault();\n    save();\n    var url = 'https://' + $('#domain').val() + '/samlp/' + $('#client_id').val() + '?RelayState=' + encodeURIComponent($('#state').val());\n    url = url + '&redirect_uri=' + encodeURIComponent(callbackUrl);\n    if ($('#connection').val() && $('#connection').val().length) {\n      url = url + '&connection=' + encodeURIComponent($('#connection').val());\n    }\n    window.location.href = url;\n  });\n  $('#wsfed').click(function(e) {\n    e.preventDefault();\n    save();\n    var url = 'https://' + $('#domain').val() + '/wsfed/' + $('#client_id').val() + '?wctx=' + encodeURIComponent($('#state').val());\n    url = url + '&wreply=' + encodeURIComponent(callbackUrl);\n    if ($('#connection').val() && $('#connection').val().length) {\n      url = url + '&wtrealm=' + encodeURIComponent($('#connection').val());\n    }\n    window.location.href = url;\n  });\n  $('#logout').click(function(e) {\n    e.preventDefault();\n    save();\n    window.location.href = 'https://' + $('#domain').val() + '/v2/logout?client_id=' + $('#client_id').val() + '&returnTo=' + encodeURIComponent(callbackUrl);\n  });\n  $('#logout-federated').click(function(e) {\n    e.preventDefault();\n    save();\n    window.location.href = 'https://' + $('#domain').val() + '/v2/logout?federated&client_id=' + $('#client_id').val() + '&returnTo=' + encodeURIComponent(callbackUrl);\n  });\n  $('#reset_settings').click(function(e) {\n    e.preventDefault();\n    for (key in localStorage) {\n      if (key.indexOf('auth_debugger_') === 0) {\n        delete localStorage[key];\n      }\n    }\n    read();\n  });\n  $('#oauth2_client_credentials').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      audience: $('#audience').val(),\n      client_id: $('#client_id').val(),\n      client_secret: $('#client_secret').val(),\n      grant_type: 'client_credentials'\n    };\n    executeRequest('OAuth2 - Client Credentials', 'https://' + $('#domain').val() + '/oauth/token', opt);\n  });\n  $('#oauth2_code_exchange').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      client_id: $('#client_id').val(),\n      redirect_uri: callbackUrl,\n      code: $('#authorization_code').val(),\n      grant_type: 'authorization_code'\n    };\n    if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {\n      opt.audience = $('#audience').val();\n    }\n    if ($('#use_pkce').is(':checked')) {\n      opt.code_verifier = $('#code_verifier').val();\n    } else {\n      opt.client_secret = $('#client_secret').val();\n    }\n    executeRequest('OAuth2 - Authorization Code Exchange', 'https://' + $('#domain').val() + '/oauth/token', opt);\n  });\n  $('#oauth2_refresh_token_exchange').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      client_id: $('#client_id').val(),\n      refresh_token: $('#refresh_token').val(),\n      grant_type: 'refresh_token'\n    };\n    if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {\n      opt.audience = $('#audience').val();\n    }\n    if ($('#use_pkce').is(':checked')) {\n      opt.code_verifier = $('#code_verifier').val();\n    } else {\n      opt.client_secret = $('#client_secret').val();\n    }\n    executeRequest('OAuth2 - Refresh Token Exchange', 'https://' + $('#domain').val() + '/oauth/token', opt);\n  });\n  $('#oauth2_password_grant').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      client_id: $('#client_id').val(),\n      username: $('#username').val(),\n      password: $('#password').val(),\n      grant_type: 'password',\n      scope: $('#scope').val()\n    };\n    if ($('#connection').val() && $('#connection').val().length) {\n      opt.connection = $('#connection').val();\n    }\n    executeRequest('OAuth2 - Password Grant', 'https://' + $('#domain').val() + '/oauth/token', opt);\n  });\n  $('#oauth2_ro').click(function(e) {\n    e.preventDefault();\n    if ($('#use_sso').is(':checked')) {\n      save();\n      var auth0 = new Auth0({\n        domain: $('#domain').val(),\n        clientID: $('#client_id').val(),\n        callbackURL: callbackUrl\n      });\n      var options = {\n        state: $('#state').val(),\n        sso: $('#use_sso').is(':checked'),\n        username: $('#username').val(),\n        password: $('#password').val(),\n        connection: $('#connection').val(),\n        scope: $('#scope').val()\n      };\n      if ($('#device').val() && $('#device').val().length) {\n        options.device = $('#device').val();\n      }\n      return auth0.login(options);\n    }\n    var opt = {\n      client_id: $('#client_id').val(),\n      username: $('#username').val(),\n      password: $('#password').val(),\n      grant_type: 'password',\n      scope: $('#scope').val()\n    };\n    if ($('#connection').val() && $('#connection').val().length) {\n      opt.connection = $('#connection').val();\n    }\n    if ($('#device').val() && $('#device').val().length) {\n      opt.device = $('#device').val();\n    }\n    executeRequest('OAuth2 - Resource Owner', 'https://' + $('#domain').val() + '/oauth/ro', opt);\n  });\n  $('#oauth2_delegation').click(function(e) {\n    e.preventDefault();\n    var opt = {\n      client_id: $('#client_id').val(),\n      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',\n      scope: $('#scope').val()\n    };\n    if ($('#delegation_target').val() && $('#delegation_target').val().length) {\n      opt.target = $('#delegation_target').val();\n    }\n    if ($('#delegation_id_token').val() && $('#delegation_id_token').val().length) {\n      opt.id_token = $('#delegation_id_token').val();\n    }\n    if ($('#delegation_refresh_token').val() && $('#delegation_refresh_token').val().length) {\n      opt.refresh_token = $('#delegation_refresh_token').val();\n    }\n    executeRequest('OAuth2 - Delegation', 'https://' + $('#domain').val() + '/delegation', opt);\n  });\n  $('#oidc_oauth2').click(function(e) {\n    e.preventDefault();\n    save();\n    // Don't do this in production. The client should always generate the verifier, and not rely on a remote server to do this.\n    $.get('{{baseUrl}}/pkce')\n      .done(function(data) {\n        var auth0 = new Auth0({\n          domain: $('#domain').val(),\n          clientID: $('#client_id').val(),\n          callbackURL: callbackUrl\n        });\n        var options = {\n          state: $('#state').val(),\n          sso: $('#use_sso').is(':checked'),\n        };\n        if ($('#use_pkce').is(':checked')) {\n          options.code_challenge = data.verifier_challenge;\n          options.code_challenge_method = 'S256';\n          localStorage.setItem('auth_debugger_code_verifier', data.verifier);\n        }\n        if ($('#scope').val() && $('#scope').val().length) {\n          options.scope = $('#scope').val();\n        }\n        if ($('#connection').val() && $('#connection').val().length) {\n          options.connection = $('#connection').val();\n        }\n        if ($('#use_audience').is(':checked') && $('#audience').val() && $('#audience').val().length) {\n          options.audience = $('#audience').val();\n        }\n        if ($('#response_type').val() && $('#response_type').val().length) {\n          options.response_type = $('#response_type').val();\n        }\n        if ($('#response_mode').val() && $('#response_mode').val().length) {\n          options.response_mode = $('#response_mode').val();\n        }\n        if ($('#prompt').val() && $('#prompt').val().length) {\n          options.prompt = $('#prompt').val();\n        }\n        auth0.login(options);\n      });\n  });\n  $('#sso-data').click(function(e) {\n    e.preventDefault();\n    save();\n    var auth0 = new Auth0({\n      domain: $('#domain').val(),\n      clientID: $('#client_id').val(),\n      callbackURL: callbackUrl\n    });\n    $('#sso-data-output').html('Loading...');\n    auth0.getSSOData(function(err, res) {\n      $.ajax({ type: \"POST\", url: '{{baseUrl}}/request', data: JSON.stringify({ error: err, response: res }), contentType: 'application/json' })\n        .done(function(data) {\n          $('#sso-data-output').html(data);\n        })\n        .fail(function(err) {\n          $('#sso-data-output').html('');\n          $('<pre/>', { 'class':'json-object', 'html': err.responseText || err.name || err.text || err.body || err.status }).appendTo('#sso-data-output');\n        });\n    });\n  });\n});\n</script>\n</body>\n</html>\n";

/***/ },
/* 122 */
/***/ function(module, exports) {

	"use strict";

	module.exports = "\n{{#if request}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>Request</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{request}}}</pre>\n  </div>\n</div>\n{{/if}}\n{{#if response}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>Response</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{response}}}</pre>\n  </div>\n</div>\n{{/if}}\n{{#if hash}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>Hash Fragment</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{hash}}}</pre>\n  </div>\n</div>\n{{/if}}\n{{#if id_token}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>ID Token</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{id_token}}}</pre>\n  </div>\n</div>\n{{/if}}\n{{#if access_token}}\n<div class=\"row\">\n  <div class=\"col-xs-12\">\n    <div>\n      <h5>Access Token</h5>\n    </div>\n  </div>\n  <div class=\"col-lg-12\">\n    <pre class=\"json-object\">{{{access_token}}}</pre>\n  </div>\n</div>\n{{/if}}\n";

/***/ }
/******/ ]);