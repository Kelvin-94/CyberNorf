import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildCsp, generateNonce } from '@/server/security/csp';

/** Splits a policy into directive -> source list so assertions stay exact. */
function directives(policy: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const directive of policy.split(';')) {
    const trimmed = directive.trim();
    if (!trimmed) {
      continue;
    }
    const [name, ...sources] = trimmed.split(/\s+/);
    if (name) {
      result.set(name, sources.join(' '));
    }
  }
  return result;
}

test('production policy binds inline script to the per-response nonce', () => {
  const nonce = 'dGVzdC1ub25jZS12YWx1ZQ==';
  const policy = directives(buildCsp({ nonce, production: true }));

  assert.equal(policy.get('default-src'), "'self'");
  // No 'unsafe-inline': an injected inline script has no nonce and is blocked.
  assert.equal(policy.get('script-src'), `'self' 'nonce-${nonce}'`);
  assert.ok(!policy.get('script-src')?.includes("'unsafe-inline'"));
  assert.ok(!policy.get('script-src')?.includes("'unsafe-eval'"));
});

test('development policy keeps the hot-reload relaxations but still no inline script', () => {
  const policy = directives(buildCsp({ nonce: 'ZGV2', production: false }));

  assert.equal(policy.get('script-src'), "'self' 'nonce-ZGV2' 'unsafe-eval'");
  assert.ok(!policy.get('script-src')?.includes("'unsafe-inline'"));
  assert.equal(policy.get('connect-src'), "'self' ws: wss:");
});

test('policy hardens the directives that turn markup injection into script', () => {
  const policy = directives(buildCsp({ nonce: 'x', production: true }));

  assert.equal(policy.get('object-src'), "'none'");
  assert.equal(policy.get('base-uri'), "'none'");
  assert.equal(policy.get('frame-ancestors'), "'none'");
  assert.equal(policy.get('form-action'), "'self'");
  // Inline style attributes cannot execute script; React/Next emit them, so the
  // allowance is deliberate and documented in the module.
  assert.equal(policy.get('style-src'), "'self' 'unsafe-inline'");
});

test('upgrade-insecure-requests is production-only', () => {
  const production = directives(buildCsp({ nonce: 'x', production: true }));
  const development = directives(buildCsp({ nonce: 'x', production: false }));

  assert.ok(production.has('upgrade-insecure-requests'));
  assert.ok(!development.has('upgrade-insecure-requests'));
});

test('each nonce is 128 bits of base64 and never repeats', () => {
  const first = generateNonce();
  const second = generateNonce();

  assert.match(first, /^[A-Za-z0-9+/]{22}==$/);
  assert.notEqual(first, second);
});
