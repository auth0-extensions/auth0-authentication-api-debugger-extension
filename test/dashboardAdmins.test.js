const assert = require('node:assert/strict');
const nock = require('nock');
const request = require('supertest');

const { AUTH0_DOMAIN, AUTH0_RTA, createApp, createSigningKey } = require('./helpers');

const HOST = 'ext.example.com';
const BASE_URL = `https://${HOST}`;
const AUDIENCE = `https://${AUTH0_DOMAIN}/api/v2/`;

describe('dashboard admins', () => {
  let app;

  before(() => {
    nock.disableNetConnect();
    nock.enableNetConnect('127.0.0.1');
    app = createApp();
  });

  afterEach(() => nock.cleanAll());

  after(() => nock.enableNetConnect());

  describe('GET /login', () => {
    it('redirects to the root tenant authority with the extension as client', async () => {
      const res = await request(app).get('/login').set('Host', HOST).expect(302);
      const location = new URL(res.headers.location);

      assert.equal(location.origin + location.pathname, `${AUTH0_RTA}/i/oauth2/authorize`);
      assert.equal(location.searchParams.get('client_id'), BASE_URL);
      assert.equal(location.searchParams.get('redirect_uri'), `${BASE_URL}/callback`);
      assert.equal(location.searchParams.get('response_mode'), 'form_post');
      assert.equal(location.searchParams.get('audience'), AUDIENCE);
      assert.equal(location.searchParams.get('scope'), 'read:clients read:client_keys openid profile');
    });
  });

  describe('GET /.well-known/oauth2-client-configuration', () => {
    it('describes the extension client', async () => {
      const res = await request(app).get('/.well-known/oauth2-client-configuration').set('Host', HOST).expect(200);

      assert.deepEqual(res.body, {
        redirect_uris: [ `${BASE_URL}/callback` ],
        client_name: 'Authentication API Debugger Extension',
        post_logout_redirect_uris: [ BASE_URL ]
      });
    });
  });

  describe('POST /callback', () => {
    const tokenFor = (key, iss, sub) => key.sign({
      iss,
      sub,
      aud: [ AUDIENCE, `${AUTH0_RTA}/userinfo` ],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300
    });

    it('accepts a token issued by the root tenant authority', async () => {
      const key = createSigningKey('rta-key');
      nock(AUTH0_RTA).get('/.well-known/jwks.json').reply(200, key.jwks);
      const token = tokenFor(key, `${AUTH0_RTA}/`, 'admin|valid');

      const res = await request(app)
        .post('/callback')
        .set('Host', HOST)
        .type('form')
        .send({ access_token: token })
        .expect(200);

      assert.match(res.text, /sessionStorage\.setItem\('token'/);
    });

    it('rejects a validly signed token from another issuer', async () => {
      const key = createSigningKey('attacker-key');
      nock('https://attacker.example.com').get('/.well-known/jwks.json').reply(200, key.jwks);
      const token = tokenFor(key, 'https://attacker.example.com/', 'admin|forged');

      const res = await request(app)
        .post('/callback')
        .set('Host', HOST)
        .type('form')
        .send({ access_token: token })
        .expect(500);

      assert.deepEqual(res.body, { message: `jwt issuer invalid. expected: ${AUTH0_RTA}/` });
    });
  });
});
