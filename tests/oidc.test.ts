import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  getOidcSignInLabel,
  oidcEmailClaimRejection,
  readOidcSettings,
} from '@/server/auth/oidc';

/**
 * Single sign-on configuration decides whether a second way into every account
 * exists, so these tests pin the two rules that matter: an incomplete provider
 * must never boot as a silent no-op or over cleartext, and the identity
 * provider's verified-email claim is the only thing that may pass the gate.
 */

const configured = {
  OIDC_ISSUER: 'https://idp.example.com/realms/cybernorf/',
  OIDC_CLIENT_ID: 'cybernorf',
  OIDC_CLIENT_SECRET: 'a-very-secret-value',
};

test('no configuration at all leaves single sign-on off', () => {
  assert.equal(readOidcSettings({}), null);
  assert.equal(getOidcSignInLabel({}), null);
});

test('a partially configured provider refuses to start', () => {
  assert.throws(
    () => readOidcSettings({ OIDC_CLIENT_ID: 'cybernorf' }),
    /OIDC_ISSUER, OIDC_CLIENT_SECRET must also be configured/,
  );
  assert.throws(() => readOidcSettings({ ...configured, OIDC_ISSUER: '   ' }), /OIDC_ISSUER/);
});

test('cleartext issuers are refused unless the provider is on loopback', () => {
  assert.throws(
    () => readOidcSettings({ ...configured, OIDC_ISSUER: 'http://idp.example.com' }),
    /must use https:\/\//,
  );
  assert.throws(
    () => readOidcSettings({ ...configured, OIDC_REDIRECT_URI: 'http://cybernorf.example.com/cb' }),
    /OIDC_REDIRECT_URI must use https:\/\//,
  );
  const loopback = readOidcSettings({ ...configured, OIDC_ISSUER: 'http://127.0.0.1:9100' });
  assert.equal(loopback?.discoveryUrl, 'http://127.0.0.1:9100/.well-known/openid-configuration');
  assert.doesNotThrow(() => readOidcSettings({ ...configured, OIDC_ISSUER: 'http://localhost:9100' }));
});

test('issuers that are not an absolute http(s) URL are refused', () => {
  assert.throws(() => readOidcSettings({ ...configured, OIDC_ISSUER: 'idp.example.com' }), /absolute/);
  assert.throws(() => readOidcSettings({ ...configured, OIDC_ISSUER: 'ftp://idp.example.com' }), /http/);
});

test('issuers with embedded credentials or query strings are refused', () => {
  assert.throws(
    () => readOidcSettings({ ...configured, OIDC_ISSUER: 'https://user:pass@idp.example.com' }),
    /must not embed credentials/,
  );
  assert.throws(
    () => readOidcSettings({ ...configured, OIDC_ISSUER: 'https://idp.example.com?x=1' }),
    /must not include a query string/,
  );
});

test('a configured provider normalizes the issuer and derives discovery', () => {
  const settings = readOidcSettings(configured);
  assert.ok(settings);
  assert.equal(settings.issuer, 'https://idp.example.com/realms/cybernorf');
  assert.equal(
    settings.discoveryUrl,
    'https://idp.example.com/realms/cybernorf/.well-known/openid-configuration',
  );
  assert.equal(settings.clientSecret, 'a-very-secret-value');
  // No display name configured falls back to a generic label.
  assert.equal(settings.displayName, 'single sign-on');
  assert.equal(settings.redirectUri, null);
});

test('the display name is collapsed and bounded', () => {
  assert.equal(getOidcSignInLabel({ ...configured, OIDC_DISPLAY_NAME: '  Acme   SSO  ' }), 'Acme SSO');
  const long = getOidcSignInLabel({ ...configured, OIDC_DISPLAY_NAME: 'x'.repeat(200) });
  assert.equal(long?.length, 40);
});

test('an explicit redirect URI is validated and kept verbatim', () => {
  const settings = readOidcSettings({
    ...configured,
    OIDC_REDIRECT_URI: 'https://sso.example.com/api/auth/callback/oidc',
  });
  assert.equal(settings?.redirectUri, 'https://sso.example.com/api/auth/callback/oidc');
});

test('the verified-email gate accepts only a boolean true claim', () => {
  assert.equal(oidcEmailClaimRejection({ email_verified: true }), null);
  for (const profile of [
    { email_verified: false },
    { email_verified: 'true' },
    { email_verified: 1 },
    {},
    undefined,
    null,
    'email_verified=true',
  ]) {
    const rejection = oidcEmailClaimRejection(profile);
    assert.equal(rejection?.error, 'email_not_verified');
  }
});
