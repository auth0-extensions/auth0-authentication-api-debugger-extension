const cors = require('cors');
const crypto = require('crypto');
const Express = require('express');
const bodyParser = require('body-parser');
const handlebars = require('handlebars');
const { middlewares, routes, urlHelpers } = require('auth0-extension-express-tools');

const config = require('./lib/config');
const utils = require('./lib/utils');
const metadata = require('../webtask.json');

module.exports = (configProvider) => {
    config.setProvider(configProvider);

    const index = handlebars.compile(require('./views'));
    const partial = handlebars.compile(require('./views/partial'));
    const app = new Express();

    const adminsOnly = middlewares.authenticateAdmins({
      credentialsRequired: true,
      secret: config('EXTENSION_SECRET'),
      audience: 'urn:authentication-api-debugger',
      baseUrl: config('PUBLIC_WT_URL'),
      onLoginSuccess: (req, res, next) => {
        next();
      }
    });

    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));

    app.use(routes.dashboardAdmins({
      secret: config('EXTENSION_SECRET'),
      audience: 'urn:authentication-api-debugger',
      rta: config('AUTH0_RTA').replace('https://', ''),
      domain: config('AUTH0_DOMAIN'),
      baseUrl: config('PUBLIC_WT_URL'),
      clientName: `Auth0 Authentication API Debugger`,
      sessionStorageKey: 'auth-api-debugger:apiToken',
    }));

    app.get('/pkce', adminsOnly, function (req, res) {
        const verifier = utils.base64url(crypto.randomBytes(32));
        return res.json({
            verifier: verifier,
            verifier_challenge: utils.base64url(crypto.createHash('sha256').update(verifier).digest())
        })
    });

    app.get('/hash', adminsOnly, function (req, res) {
        res.send(partial({
            hash: utils.syntaxHighlight(req.query),
            id_token: utils.jwt(req.query && req.query.id_token),
            access_token: utils.jwt(req.query && req.query.access_token)
        }));
    });

    app.post('/request', adminsOnly, function (req, res) {
        const request = req.body.request;
        delete req.body.request;
        res.send(partial({
            request: utils.syntaxHighlight(request),
            response: utils.syntaxHighlight(req.body),
            id_token: utils.jwt(req.body && req.body.id_token),
            access_token: utils.jwt(req.body && req.body.access_token)
        }));
    });

    app.get('/meta', cors(), function (req, res) {
        res.status(200).send(metadata);
    });

    const renderIndex = function (req, res) {
        const headers = req.headers;
        delete headers['x-wt-params'];

        res.send(index({
            method: req.method,
            domain: config('AUTH0_DOMAIN'),
            baseUrl: urlHelpers.getBaseUrl(req).replace('http://', 'https://'),
            headers: utils.syntaxHighlight(req.headers),
            body: utils.syntaxHighlight(req.body),
            query: utils.syntaxHighlight(req.query),
            authorization_code: req.query && req.query.code,
            samlResponse: utils.samlResponse(req.body && req.body.SAMLResponse),
            wsFedResult: utils.wsFedResult(req.body && req.body.wresult),
            id_token: utils.jwt(req.body && req.body.id_token),
            access_token: utils.jwt(req.body && req.body.access_token)
        }));
    };

    app.get('*', renderIndex);
    app.post('*', renderIndex);

    return app;
};
