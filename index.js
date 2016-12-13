const path = require('path');
const crypto = require('crypto');
const express = require('express')
const bodyParser = require('body-parser')
const handlebars = require('handlebars');
const Webtask = require('webtask-tools');
const expressTools = require('auth0-extension-express-tools');
const middlewares = require('auth0-extension-express-tools').middlewares;
const auth0 = require('auth0-oauth2-express');
const tools = require('auth0-extension-tools');
var _ = require('lodash');
var config = require('auth0-extension-tools').config();
const dashboardAdmins = require('./middleware/dashboardAdmins.js');

var metadata = require('./webtask.json');
var ManagementClient = require('auth0').ManagementClient;

module.exports = function (configProvider, storageProvider) {
    const utils = require('./lib/utils');
    const index = handlebars.compile(require('./views/index'));
    const partial = handlebars.compile(require('./views/partial'));

    config.setProvider(configProvider);

    const app = express();
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));
    
    app.use(require('./middleware/develop.js'));

    // const options = {
    //     credentialsRequired: false,
    //     scopes: 'create:users read:users read:connections',
    //     clientName: title,
    //     audience: function () {
    //         return 'https://' + config('AUTH0_DOMAIN') + '/api/v2/';
    //     },
    //     rootTenantAuthority: config('AUTH0_RTA')
    // };
    // app.use(function (req, res, next) {
    //     auth0({
    //         scopes: 'read:clients read:client_keys',
    //         audience: function () {
                
    //         },
    //         rootTenantAuthority: 
    //     })(req, res, next)
    // });
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

    app.get('/meta', function (req, res) {
        res.status(200).send(metadata);
    });

    const renderIndex = function (req, res) {
        const headers = req.headers;
        delete headers['x-wt-params'];

        res.send(index({
            method: req.method,
            domain: req.webtaskContext.data.AUTH0_DOMAIN,
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
    };

    app.get('*', renderIndex);
    app.post('*', renderIndex);

    return app;
}
