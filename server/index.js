const cors = require('cors');
const crypto = require('crypto');
const Express = require('express');
const bodyParser = require('body-parser');
const handlebars = require('handlebars');
const { urlHelpers } = require('auth0-extension-express-tools');

const config = require('./lib/config');
const utils = require('./lib/utils');
const metadata = require('../webtask.json');
const dashboardAdmins = require('./middleware/dashboardAdmins');
const AuthenticationClient = require('auth0').AuthenticationClient;

module.exports = (configProvider) => {
    config.setProvider(configProvider);

    const index = handlebars.compile(require('./views'));
    const partial = handlebars.compile(require('./views/partial'));
    const app = new Express();


    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));

    app.use(dashboardAdmins(config('AUTH0_DOMAIN'), 'Authentication API Debugger Extension', config('AUTH0_RTA')));

    app.get('/pkce', function (req, res) {
        const verifier = utils.base64url(crypto.randomBytes(32));
        return res.json({
            verifier: verifier,
            verifier_challenge: utils.base64url(crypto.createHash('sha256').update(verifier).digest())
        })
    });

    app.get('/hash', function (req, res) {
        res.send(partial({
            hash: utils.syntaxHighlight(req.query),
            id_token: utils.jwt(req.query && req.query.id_token),
            access_token: utils.jwt(req.query && req.query.access_token)
        }));
    });

    app.post('/request', function (req, res) {
        const request = req.body.request;
        delete req.body.request;
        res.send(partial({
            request: utils.syntaxHighlight(request),
            response: utils.syntaxHighlight(req.body),
            id_token: utils.jwt(req.body && req.body.id_token),
            access_token: utils.jwt(req.body && req.body.access_token)
        }));
    });

    app.post('/request/code', function(req, res) {
        const data = {
          code: req.body.code,
          redirect_uri: req.body.redirect_uri,
          code_verifier: req.body.code_verifier
        };
        const auth0 = new AuthenticationClient({
          domain: config('AUTH0_DOMAIN'),
          clientId: req.body.client_id,
          clientSecret: req.body.client_secret,
          __bypassIdTokenValidation: true
        });

        auth0.oauth.authorizationCodeGrant(data, function (err, response) {
          if (err) {
            const data = utils.tryParseJSON(err.message);
            return res.status(err.statusCode).json(data);
          }
          res.json(response);
        });
      });

    app.post('/request/token', function(req, res) {
        const auth0 = new AuthenticationClient({
            domain: config('AUTH0_DOMAIN'),
            clientId: req.body.client_id,
            clientSecret: req.body.client_secret,
            __bypassIdTokenValidation: true
        });

        const data = { refresh_token: req.body.refresh_token, client_secret: req.body.client_secret };
        auth0.oauth.refreshToken(data, function (err, response) {
            if (err) {
                const data = utils.tryParseJSON(err.message);
                return res.status(err.statusCode).json(data);
            }
            res.json(response);
        });
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
