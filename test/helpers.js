const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const AUTH0_DOMAIN = 'tenant.example.auth0.com';
const AUTH0_RTA = 'https://rta.example.auth0.com';

const settings = {
  AUTH0_DOMAIN,
  AUTH0_RTA,
  NODE_ENV: 'production'
};

// The extension reads NODE_ENV at request time (auth0-oauth2-express).
process.env.NODE_ENV = 'production';

const createApp = () => require('../server')((key) => settings[key]);

const base64url = (value) => Buffer.from(value).toString('base64url');

// auth0-api-jwt-rsa-validation only accepts keys published with an x5c certificate,
// so generate a throwaway self-signed certificate instead of committing one.
const createSigningKey = (kid) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'apidebug-test-'));
  const keyFile = path.join(dir, 'key.pem');
  const certFile = path.join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=test', '-keyout', keyFile, '-out', certFile
  ], { stdio: 'ignore' });

  const privateKey = fs.readFileSync(keyFile, 'utf8');
  const x5c = fs.readFileSync(certFile, 'utf8')
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
    .replace(/\s/g, '');
  fs.rmSync(dir, { recursive: true, force: true });

  return {
    jwks: { keys: [ { kty: 'RSA', use: 'sig', kid, x5c: [ x5c ] } ] },
    sign: (payload) => {
      const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid }));
      const body = base64url(JSON.stringify(payload));
      const signature = crypto.sign('RSA-SHA256', Buffer.from(`${header}.${body}`), privateKey);
      return `${header}.${body}.${signature.toString('base64url')}`;
    }
  };
};

const unsignedJwt = (payload) =>
  `${base64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${base64url(JSON.stringify(payload))}.`;

module.exports = {
  AUTH0_DOMAIN,
  AUTH0_RTA,
  createApp,
  createSigningKey,
  unsignedJwt
};
