import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertSecureTransport } from './config.ts';

const HTTPS = 'https://cybernorf.example';
const REMOTE_DB = 'postgresql://user:pw@db.internal:5432/cybernorf?schema=public';

test('development is never blocked by transport checks', () => {
  assert.doesNotThrow(() =>
    assertSecureTransport({
      production: false,
      origin: 'http://localhost:3000',
      databaseUrl: REMOTE_DB,
    }),
  );
});

test('production accepts an https origin with a TLS database', () => {
  assert.doesNotThrow(() =>
    assertSecureTransport({
      production: true,
      origin: HTTPS,
      databaseUrl: `${REMOTE_DB}&sslmode=verify-full`,
    }),
  );
});

test('production rejects a plain-http origin on a real host', () => {
  for (const origin of ['http://cybernorf.example', 'http://192.168.178.10:3000']) {
    assert.throws(
      () =>
        assertSecureTransport({
          production: true,
          origin,
          databaseUrl: `${REMOTE_DB}&sslmode=require`,
        }),
      /BETTER_AUTH_URL must be an https:\/\/ origin/,
    );
  }
});

test('production rejects an empty origin', () => {
  // An omitted argument falls back to process.env, so test the empty string.
  assert.throws(
    () =>
      assertSecureTransport({
        production: true,
        origin: '',
        databaseUrl: `${REMOTE_DB}&sslmode=require`,
      }),
    /BETTER_AUTH_URL must be set to an absolute origin/,
  );
});

test('production rejects an origin that is not a URL', () => {
  assert.throws(
    () =>
      assertSecureTransport({
        production: true,
        origin: 'not-an-origin',
        databaseUrl: `${REMOTE_DB}&sslmode=require`,
      }),
    /BETTER_AUTH_URL must be set to an absolute origin/,
  );
});

test('production allows a loopback http origin for local smoke runs', () => {
  for (const origin of ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000']) {
    assert.doesNotThrow(() =>
      assertSecureTransport({
        production: true,
        origin,
        databaseUrl: `${REMOTE_DB}&sslmode=require`,
      }),
    );
  }
});

test('production rejects a remote database without TLS', () => {
  assert.throws(
    () => assertSecureTransport({ production: true, origin: HTTPS, databaseUrl: REMOTE_DB }),
    /DATABASE_URL must request TLS/,
  );
});

test('production rejects sslmode=disable for a remote database', () => {
  assert.throws(
    () =>
      assertSecureTransport({
        production: true,
        origin: HTTPS,
        databaseUrl: `${REMOTE_DB}&sslmode=disable`,
      }),
    /DATABASE_URL must request TLS/,
  );
});

test('a loopback or unix-socket database does not need TLS', () => {
  for (const databaseUrl of [
    'postgresql://cybernorf:cybernorf@localhost:55432/cybernorf?schema=public',
    'postgresql://cybernorf:cybernorf@127.0.0.1:5432/cybernorf?schema=public',
    'postgresql://cybernorf:cybernorf@/cybernorf?host=/var/run/postgresql',
  ]) {
    assert.doesNotThrow(() =>
      assertSecureTransport({ production: true, origin: HTTPS, databaseUrl }),
    );
  }
});
