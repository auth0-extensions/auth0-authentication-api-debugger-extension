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

	var express = __webpack_require__(3);
	var auth0 = __webpack_require__(4);
	var Webtask = __webpack_require__(1);
	var app = express();
	var metadata = __webpack_require__(5);

	app.use(auth0({
	  scopes: 'read:connections'
	}));

	app.get('/', function (req, res) {
	  var view = ['<html>', '  <head>', '    <title>Auth0 Extension</title>', '    <script type="text/javascript">', '       if (!sessionStorage.getItem("token")) {', '         window.location.href = "' + res.locals.baseUrl + '/login";', '       }', '    </script>', '  </head>', '  <body>', '    <p><strong>Token</strong></p>', '    <textarea rows="10" cols="100" id="token"></textarea>', '    <script type="text/javascript">', '       var token = sessionStorage.getItem("token");', '       if (token) {', '         document.getElementById("token").innerText = token;', '       }', '    </script>', '  </body>', '</html>'].join('\n');

	  res.header("Content-Type", 'text/html');
	  res.status(200).send(view);
	});

	// This endpoint would be called by webtask-gallery to dicover your metadata
	app.get('/meta', function (req, res) {
	  res.status(200).send(metadata);
	});

	module.exports = app;

/***/ },
/* 3 */
/***/ function(module, exports) {

	module.exports = require("express");

/***/ },
/* 4 */
/***/ function(module, exports) {

	module.exports = require("auth0-oauth2-express");

/***/ },
/* 5 */
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

/***/ }
/******/ ]);