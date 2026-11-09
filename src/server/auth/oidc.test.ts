import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getOidcSignInLabel, readOidcSettings } from './oidc.ts';

const COMPLETE = {
  OIDC_ISSUER: 'https://idp.example.com',
  OIDC_CLIENT_ID: 'cybernorf-console',
  OIDC_CLIENT_SECRET: 'client-secret-value',
};

test('single sign-on stays off when nothing is configured', () => {
  assert.equal(readOidcSettings({}), null);
  assert.equal(readOidcSettings({ OIDC_ISSUER: '   ', OIDC_DISPLAY_NAME: 'Okta' }), null);
  assert.equal(getOidcSignInLabel({}), null);
});

test('a partial configuration is refused instead of silently ignored', () => {
  assert.throws(
    () => readOidcSettings({ OIDC_ISSUER: COMPLETE.OIDC_ISSUER }),
    /OIDC_CLIENT_ID, OIDC_CLIENT_SECRET must also be configured/,
  );
  assert.throws(
    () => readOidcSettings({ ...COMPLETE, OIDC_CLIENT_SECRET: '  ' }),
    /OIDC_CLIENT_SECRET/,
  );
});

test('discovery is derived from the issuer with a trailing slash removed', () => {
  const settings = readOidcSettings({ ...COMPLETE, OIDC_ISSUER: 'https://idp.example.com//' });
  assert.equal(settings?.issuer, 'https://idp.example.com');
  assert.equal(settings?.discoveryUrl, 'https://idp.example.com/.well-known/openid-configuration');
  assert.equal(settings?.clientId, COMPLETE.OIDC_CLIENT_ID);
  assert.equal(settings?.clientSecret, COMPLETE.OIDC_CLIENT_SECRET);
  assert.equal(settings?.redirectUri, null);
});

test('an issuer path is preserved for multi-tenant providers', () => {
  const settings = readOidcSettings({
    ...COMPLETE,
    OIDC_ISSUER: 'https://idp.example.com/realms/acme/',
  });
  assert.equal(settings?.issuer, 'https://idp.example.com/realms/acme');
  assert.equal(
    settings?.discoveryUrl,
    'https://idp.example.com/realms/acme/.well-known/openid-configuration',
  );
});

test('a remote provider must be reached over https', () => {
  assert.throws(
    () => readOidcSettings({ ...COMPLETE, OIDC_ISSUER: 'http://idp.example.com' }),
    /must use https:\/\//,
  );
  assert.throws(
    () => readOidcSettings({ ...COMPLETE, OIDC_REDIRECT_URI: 'http://cybernorf.example.com/cb' }),
    /OIDC_REDIRECT_URI must use https:\/\//,
  );
});

test('a loopback provider is accepted for local development', () => {
  const settings = readOidcSettings({ ...COMPLETE, OIDC_ISSUER: 'http://127.0.0.1:9100/' });
  assert.equal(settings?.issuer, 'http://127.0.0.1:9100');
  assert.equal(settings?.discoveryUrl, 'http://127.0.0.1:9100/.well-known/openid-configuration');
});

test('malformed issuers are rejected', () => {
  assert.throws(
    () => readOidcSettings({ ...COMPLETE, OIDC_ISSUER: 'idp.example.com' }),
    /absolute/,
  );
  assert.throws(
    () => readOidcSettings({ ...COMPLETE, OIDC_ISSUER: 'ftp://idp.example.com' }),
    /http/,
  );
  assert.throws(
    () => readOidcSettings({ ...COMPLETE, OIDC_ISSUER: 'https://user:pw@idp.example.com' }),
    /must not embed credentials/,
  );
  assert.throws(
    () => readOidcSettings({ ...COMPLETE, OIDC_ISSUER: 'https://idp.example.com/?tenant=1' }),
    /query string or fragment/,
  );
});

test('the sign-in label falls back, is collapsed, and is capped', () => {
  assert.equal(readOidcSettings(COMPLETE)?.displayName, 'single sign-on');
  assert.equal(
    readOidcSettings({ ...COMPLETE, OIDC_DISPLAY_NAME: '  Acme   Okta ' })?.displayName,
    'Acme Okta',
  );
  assert.equal(getOidcSignInLabel({ ...COMPLETE, OIDC_DISPLAY_NAME: 'Acme Okta' }), 'Acme Okta');
  assert.equal(
    readOidcSettings({ ...COMPLETE, OIDC_DISPLAY_NAME: 'x'.repeat(80) })?.displayName?.length,
    40,
  );
});

test('an explicit redirect URI is validated and kept verbatim', () => {
  assert.equal(
    readOidcSettings({
      ...COMPLETE,
      OIDC_REDIRECT_URI: 'https://sso.example.com/api/auth/callback/oidc',
    })?.redirectUri,
    'https://sso.example.com/api/auth/callback/oidc',
  );
});
