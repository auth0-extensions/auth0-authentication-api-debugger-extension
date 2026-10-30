const assert = require('node:assert/strict');
const crypto = require('crypto');
const nock = require('nock');
const request = require('supertest');

const { AUTH0_DOMAIN, createApp, unsignedJwt } = require('./helpers');
const metadata = require('../webtask.json');

describe('server', () => {
  let app;

  before(() => {
    nock.disableNetConnect();
    nock.enableNetConnect('127.0.0.1');
    app = createApp();
  });

  afterEach(() => nock.cleanAll());

  after(() => nock.enableNetConnect());

  describe('GET /meta', () => {
    it('returns the extension metadata with CORS enabled', async () => {
      const res = await request(app).get('/meta').expect(200);

      assert.deepEqual(res.body, metadata);
      assert.equal(res.headers['access-control-allow-origin'], '*');
    });
  });

  describe('GET /pkce', () => {
    it('returns a verifier and its S256 challenge', async () => {
      const res = await request(app).get('/pkce').expect(200);
      const { verifier, verifier_challenge: challenge } = res.body;

      assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
      assert.equal(challenge, crypto.createHash('sha256').update(verifier).digest('base64url'));
    });
  });

  describe('GET /hash', () => {
    it('renders the query and decodes the tokens', async () => {
      const idToken = unsignedJwt({ sub: 'user|hash-test' });
      const res = await request(app).get('/hash').query({ id_token: idToken, state: 'abc' }).expect(200);

      assert.match(res.text, /user\|hash-test/);
      assert.match(res.text, /json-key/);
    });
  });

  describe('POST /request', () => {
    it('renders the request and the response', async () => {
      const res = await request(app)
        .post('/request')
        .send({ request: { grant_type: 'client_credentials' }, access_token: unsignedJwt({ scope: 'read:stuff' }) })
        .expect(200);

      assert.match(res.text, /client_credentials/);
      assert.match(res.text, /read:stuff/);
    });
  });

  describe('POST /request/code', () => {
    it('exchanges the authorization code with the tenant', async () => {
      let body;
      nock(`https://${AUTH0_DOMAIN}`)
        .post('/oauth/token', (b) => { body = b; return true; })
        .reply(200, { access_token: 'at', token_type: 'Bearer' });

      const res = await request(app)
        .post('/request/code')
        .send({
          client_id: 'client',
          client_secret: 'secret',
          code: 'the-code',
          redirect_uri: 'https://callback',
          code_verifier: 'the-verifier'
        })
        .expect(200);

      assert.deepEqual(res.body, { access_token: 'at', token_type: 'Bearer' });
      assert.equal(body.grant_type, 'authorization_code');
      assert.equal(body.client_id, 'client');
      assert.equal(body.client_secret, 'secret');
      assert.equal(body.code, 'the-code');
      assert.equal(body.redirect_uri, 'https://callback');
      assert.equal(body.code_verifier, 'the-verifier');
    });

    it('passes the tenant error through', async () => {
      nock(`https://${AUTH0_DOMAIN}`)
        .post('/oauth/token')
        .reply(403, { error: 'invalid_grant', error_description: 'Invalid authorization code' });

      const res = await request(app)
        .post('/request/code')
        .send({ client_id: 'client', client_secret: 'secret', code: 'bad', redirect_uri: 'https://callback' })
        .expect(403);

      assert.equal(res.body.error, 'invalid_grant');
      assert.equal(res.body.error_description, 'Invalid authorization code');
    });
  });

  describe('POST /request/token', () => {
    it('exchanges the refresh token with the tenant', async () => {
      let body;
      nock(`https://${AUTH0_DOMAIN}`)
        .post('/oauth/token', (b) => { body = b; return true; })
        .reply(200, { access_token: 'refreshed', token_type: 'Bearer' });

      const res = await request(app)
        .post('/request/token')
        .send({ client_id: 'client', client_secret: 'secret', refresh_token: 'the-refresh-token' })
        .expect(200);

      assert.deepEqual(res.body, { access_token: 'refreshed', token_type: 'Bearer' });
      assert.equal(body.grant_type, 'refresh_token');
      assert.equal(body.client_id, 'client');
      assert.equal(body.client_secret, 'secret');
      assert.equal(body.refresh_token, 'the-refresh-token');
    });

    it('passes the tenant error through', async () => {
      nock(`https://${AUTH0_DOMAIN}`)
        .post('/oauth/token')
        .reply(403, { error: 'invalid_grant', error_description: 'Unknown or invalid refresh token.' });

      const res = await request(app)
        .post('/request/token')
        .send({ client_id: 'client', client_secret: 'secret', refresh_token: 'bad' })
        .expect(403);

      assert.equal(res.body.error, 'invalid_grant');
    });
  });

  describe('index page', () => {
    it('renders on GET with the tenant domain and an https base url', async () => {
      const res = await request(app).get('/').set('Host', 'ext.example.com').expect(200);

      assert.match(res.text, new RegExp(`value="${AUTH0_DOMAIN}"`));
      assert.match(res.text, /https:\/\/ext\.example\.com/);
    });

    it('renders a posted SAML response', async () => {
      const saml = Buffer.from('<samlp:Response><saml:Issuer>urn:test-issuer</saml:Issuer></samlp:Response>').toString('base64');
      const res = await request(app).post('/').type('form').send({ SAMLResponse: saml }).expect(200);

      assert.match(res.text, /urn:test-issuer/);
      assert.match(res.text, /&lt;samlp:Response&gt;/);
    });

    it('renders a posted WS-Fed result', async () => {
      const res = await request(app).post('/').type('form').send({ wresult: '<t:RequestSecurityTokenResponse>urn:wsfed</t:RequestSecurityTokenResponse>' }).expect(200);

      assert.match(res.text, /urn:wsfed/);
    });
  });
});
