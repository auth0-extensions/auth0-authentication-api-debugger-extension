const path = require('path');
const crypto = require('crypto');
const express = require('express')
const bodyParser = require('body-parser')
const handlebars = require('handlebars');
const Webtask = require('webtask-tools');
const expressTools = require('auth0-extension-express-tools');
const middlewares = require('auth0-extension-express-tools').middlewares;
//const config = require('auth0-extension-tools').config();
//const auth0 = require('auth0-oauth2-express');
const tools = require('auth0-extension-tools');
var _ = require('lodash');

var metadata = require('./webtask.json');
var ManagementClient = require('auth0').ManagementClient;

const utils = require('./lib/utils');
const index = handlebars.compile(require('./views/index'));
const partial = handlebars.compile(require('./views/partial'));

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(require('./middleware/develop.js'));

// app.use(middlewares.managementApiClient({
//     // domain: req.webtaskContext.data.AUTH0_DOMAIN,
//     // clientId: req.webtaskContext.data.AUTH0_CLIENT_ID,
//     // clientSecret: req.webtaskContext.data.AUTH0_CLIENT_SECRET
//     domain: 'jerrie.auth0.com',
//     clientId: '8SsThyk5D2T2QjD5yL6lQL8O4xO7ecrl',
//     clientSecret: 'JnLYxKhY8LR5lK_CQpZzE2O0YV5r8awekRLQys3-H_iGnnqqpdZxk3eLP4NB_6yr'

// }));

// app.use(function (req, res, next) {
//   auth0({
//     scopes: 'read:clients read:client_keys'
//   })(req, res, next)
// });

// app.get('/clients', function (req, res) {
//   var token = req.headers.authorization.split(' ')[1];

//   var management = new ManagementClient({
//     token: token,
//     domain: req.webtaskContext.data.AUTH0_DOMAIN
//   });

//   management.clients.getAll(function (err, clients) {
//     res.json(_.map(clients, function (elm) { return _.pick(elm, 'name', 'client_id', 'client_secret') }));
//   });
// });

app.get('/pkce', function(req, res) {
    const verifier = utils.base64url(crypto.randomBytes(32));
    return res.json({
        verifier: verifier,
        verifier_challenge: utils.base64url(crypto.createHash('sha256').update(verifier).digest())
    })
});

app.get('/hash', function(req, res) {
    res.send(partial({
        hash: utils.syntaxHighlight(req.query),
        id_token: utils.jwt(req.query && req.query.id_token),
        access_token: utils.jwt(req.query && req.query.access_token)
    }));
});

app.post('/request', function(req, res) {
    const request = req.body.request;
    delete req.body.request;
    res.send(partial({
        request: utils.syntaxHighlight(request),
        response: utils.syntaxHighlight(req.body),
        id_token: utils.jwt(req.body && req.body.id_token),
        access_token: utils.jwt(req.body && req.body.access_token)
    }));
});

app.get('/meta', function(req, res) {
    res.status(200).send(metadata);
});

function getClients() {
    // var management = new ManagementClient({
    //   token: nconf.get('AUTH0_TOKEN'),
    //   domain: nconf.get('AUTH0_DOMAIN')
    // });

    // return management.clients.getAll();
}

const renderIndex = function(req, res) {
    var options = {
        domain: req.webtaskContext.data.AUTH0_DOMAIN,
        clientId: req.webtaskContext.data.AUTH0_CLIENT_ID,
        clientSecret: req.webtaskContext.data.AUTH0_CLIENT_SECRET
    };

    tools.managementApi.getClient(options)
        .then(function(apiClient) {
            // Use the client...
            apiClient.clients.getAll(function(err, clients) {
                try {
                    clients = _.sortBy(clients, function(client) {
                        return client.name;
                    });

                    const headers = req.headers;
                    delete headers['x-wt-params'];

                    res.send(index({
                        method: req.method,
                        domain: req.webtaskContext.data.AUTH0_DOMAIN,
                        clients: clients,
                        client_id: clients[0].client_id,
                        client_secret: clients[0].client_secret,
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

            })
        });
    // req.auth0.clients.getAll().then(function(clients) {
    //     try {
    //         clients = _.sortBy(clients, function(client) {
    //             return client.name;
    //         });

    //         const headers = req.headers;
    //         delete headers['x-wt-params'];

    //         res.send(index({
    //             method: req.method,
    //             domain: req.webtaskContext.data.AUTH0_DOMAIN,
    //             clients: clients,
    //             client_id: clients[0].client_id,
    //             client_secret: clients[0].client_secret,
    //             baseUrl: expressTools.urlHelpers.getBaseUrl(req), //.replace('http://', 'https://'),
    //             headers: utils.syntaxHighlight(req.headers),
    //             body: utils.syntaxHighlight(req.body),
    //             query: utils.syntaxHighlight(req.query),
    //             authorization_code: req.query && req.query.code,
    //             samlResponse: utils.samlResponse(req.body && req.body.SAMLResponse),
    //             wsFedResult: utils.wsFedResult(req.body && req.body.wresult),
    //             id_token: utils.jwt(req.body && req.body.id_token),
    //             access_token: utils.jwt(req.body && req.body.access_token)
    //         }));
    //     } catch (e) {
    //         console.log(e);
    //         res.json(e);
    //     }
    // });

    // try {
    //   var clients = [];

    //   const headers = req.headers;
    //   delete headers['x-wt-params'];

    //   res.send(index({
    //     data: JSON.stringify(req.webtaskContext),
    //     method: req.method,
    //     domain: '',
    //     clients: clients,
    //     client_id: '', //clients[0].client_id,
    //     client_secret: '', //clients[0].client_secret,
    //     baseUrl: expressTools.urlHelpers.getBaseUrl(req), //.replace('http://', 'https://'),
    //     headers: utils.syntaxHighlight(req.headers),
    //     body: utils.syntaxHighlight(req.body),
    //     query: utils.syntaxHighlight(req.query),
    //     authorization_code: req.query && req.query.code,
    //     samlResponse: utils.samlResponse(req.body && req.body.SAMLResponse),
    //     wsFedResult: utils.wsFedResult(req.body && req.body.wresult),
    //     id_token: utils.jwt(req.body && req.body.id_token),
    //     access_token: utils.jwt(req.body && req.body.access_token)
    //   }));
    // } catch (e) {
    //   console.log(e);
    //   res.json(e);
    // }

};

app.get('*', renderIndex);
app.post('*', renderIndex);

module.exports = app; //Webtask.fromExpress(app);