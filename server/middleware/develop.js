const path = require('path');
const express = require('express');
const dev = express.Router();
const nconf = require('nconf');

if ((process.env.NODE_ENV || 'development') === 'development') {

  nconf
    .argv()
    .env()
    .file(path.join(__dirname, './../config.json'));

  var token = require('crypto').randomBytes(32).toString('hex');

  dev.use(function (req, res, next) {
    req.webtaskContext = {
      data: {
        EXTENSION_SECRET: token,
        AUTH0_DOMAIN: nconf.get('AUTH0_DOMAIN'),
        AUTH0_CLIENT_ID: nconf.get('AUTH0_CLIENT_ID'),
        AUTH0_CLIENT_SECRET: nconf.get('AUTH0_CLIENT_SECRET')
      }
    };

    next();
  });
}

module.exports = dev;
