const path = require('path');
const nconf = require('nconf');
const logger = require('./server/lib/logger');

// eslint-disable-next-line import/no-extraneous-dependencies
require('@babel/register')({
  ignore: [ /node_modules/ ],
  sourceMaps: !(process.env.NODE_ENV === 'production'),
  plugins: [
    '@babel/plugin-proposal-export-default-from',
    '@babel/plugin-proposal-object-rest-spread'
  ],
  presets: [
    [ '@babel/env', {
      targets: {
        node: 'current'
      }
    } ]
  ]
});
// eslint-disable-next-line import/no-extraneous-dependencies
require('@babel/polyfill');

// Handle uncaught.
process.on('uncaughtException', (err) => {
  logger.error(err);
});

// Initialize configuration.
nconf
  .argv()
  .env()
  .file(path.join(__dirname, './server/config.json'))
  .defaults({
    NODE_ENV: 'development',
    HOSTING_ENV: 'default',
    PORT: 3000,
    AUTH0_RTA: 'auth0.auth0.com',
    EXTENSION_SECRET: 'secret'
  });

// Start the server.
const app = require('./server')((key) => nconf.get(key), null);
const port = nconf.get('PORT');

app.listen(port, (error) => {
  if (error) {
    logger.error(error);
  } else {
    logger.info(`Listening on http://localhost:${port}.`);
  }
});
