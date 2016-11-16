const path = require('path');
const crypto = require('crypto');
const express = require('express')
const bodyParser = require('body-parser')
const handlebars = require('handlebars');
const Webtask = require('webtask-tools');
const expressTools = require('auth0-extension-express-tools');
//const nconf = require('nconf');
var _ = require('lodash');

var metadata = require('./webtask.json');
var ManagementClient = require('auth0').ManagementClient;

const utils = require('./lib/utils');
const index = handlebars.compile(require('./views/index'));
const partial = handlebars.compile(require('./views/partial'));

// nconf
//   .argv()
//   .env()
//   .file(path.join(__dirname, './config.json'));
  
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(function (req, res, next) {
  auth0({
    scopes:              req.webtaskContext.data.AUTH0_SCOPES,
    clientId:            req.webtaskContext.data.AUTH0_CLIENT_ID,
    rootTenantAuthority: 'https://' + req.webtaskContext.data.AUTH0_DOMAIN
  })(req, res, next)
});

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

function getClients() {
  var management = new ManagementClient({
    token: nconf.get('AUTH0_TOKEN'),
    domain: nconf.get('AUTH0_DOMAIN')
  });

  return management.clients.getAll();
}

const renderIndex = function (req, res) {
  // getClients().then(function (clients) {
  //   try {
  //     clients = _.sortBy(clients, function(client) {
  //       return client.name;
  //     });

  //     const headers = req.headers;
  //     delete headers['x-wt-params'];

  //     res.send(index({
  //       method: req.method,
  //       domain: nconf.get('AUTH0_DOMAIN'),
  //       clients: clients,
  //       client_id: clients[0].client_id,
  //       client_secret: clients[0].client_secret,
  //       baseUrl: expressTools.urlHelpers.getBaseUrl(req), //.replace('http://', 'https://'),
  //       headers: utils.syntaxHighlight(req.headers),
  //       body: utils.syntaxHighlight(req.body),
  //       query: utils.syntaxHighlight(req.query),
  //       authorization_code: req.query && req.query.code,
  //       samlResponse: utils.samlResponse(req.body && req.body.SAMLResponse),
  //       wsFedResult: utils.wsFedResult(req.body && req.body.wresult),
  //       id_token: utils.jwt(req.body && req.body.id_token),
  //       access_token: utils.jwt(req.body && req.body.access_token)
  //     }));
  //   } catch (e) {
  //     console.log(e);
  //     res.json(e);
  //   }
  // });

    try {
      var clients = [];

      const headers = req.headers;
      delete headers['x-wt-params'];

      res.send(index({
        method: req.method,
        domain: '',
        clients: clients,
        client_id: '', //clients[0].client_id,
        client_secret: '', //clients[0].client_secret,
        baseUrl: expressTools.urlHelpers.getBaseUrl(req), //.replace('http://', 'https://'),
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



