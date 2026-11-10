import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { boundDiscoveryFetch, DISCOVERY_TIMEOUT_MS } from '@/server/auth/discovery-fetch';

/**
 * The identity provider's discovery document is fetched while Better Auth
 * initialises its generic OAuth plugin, and that first fetch has no timeout.
 * These tests pin the workaround: only the configured discovery URL gains a
 * bound, a signal the caller already holds is preserved by combining it, and
 * every other request passes through untouched.
 */

const discovery = 'https://idp.example.com/.well-known/openid-configuration';
const tokenEndpoint = 'https://idp.example.com/oauth/token';

type RecordedCall = { input: RequestInfo | URL; init?: RequestInit | undefined };

const calls: RecordedCall[] = [];
const originalFetch = globalThis.fetch;

globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  calls.push({ input, init });
  return Promise.resolve(new Response('{}', { status: 200 }));
}) as typeof fetch;

boundDiscoveryFetch(discovery, 200);

test('the startup discovery request is given an abort signal', async () => {
  assert.equal(DISCOVERY_TIMEOUT_MS, 5_000);

  await globalThis.fetch(discovery);
  const signal = calls.at(-1)?.init?.signal;
  assert.ok(signal instanceof AbortSignal, 'discovery must carry a signal');
  assert.equal(signal.aborted, false);

  await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
  assert.equal(signal.aborted, true, 'the signal must fire once the bound elapses');
});

test('requests to any other URL are passed through unchanged', async () => {
  await globalThis.fetch(tokenEndpoint, { method: 'POST' });
  assert.equal(calls.at(-1)?.init?.signal, undefined);
  assert.equal(calls.at(-1)?.init?.method, 'POST');
});

test('a signal supplied by the caller is combined with the bound, not replaced', async () => {
  const controller = new AbortController();
  await globalThis.fetch(discovery, { signal: controller.signal });
  const signal = calls.at(-1)?.init?.signal;

  assert.ok(signal instanceof AbortSignal);
  assert.notEqual(signal, controller.signal, 'cancellation must survive the wrapper');
  assert.equal(signal.aborted, false);

  controller.abort();
  assert.equal(signal.aborted, true);
});

test('Request and URL inputs are matched as well as strings', async () => {
  await globalThis.fetch(new Request(discovery));
  assert.ok(calls.at(-1)?.init?.signal instanceof AbortSignal);

  await globalThis.fetch(new URL(discovery));
  assert.ok(calls.at(-1)?.init?.signal instanceof AbortSignal);
});

test('installing for another URL extends the wrapper instead of stacking it', async () => {
  const secondDiscovery = 'https://other.example.com/.well-known/openid-configuration';
  const wrapped = globalThis.fetch;

  boundDiscoveryFetch(secondDiscovery, 200);
  assert.equal(globalThis.fetch, wrapped);

  await globalThis.fetch(secondDiscovery);
  assert.ok(calls.at(-1)?.init?.signal instanceof AbortSignal);

  await globalThis.fetch(discovery);
  assert.ok(calls.at(-1)?.init?.signal instanceof AbortSignal);
});

test('an invalid discovery URL is refused at startup', () => {
  assert.throws(() => boundDiscoveryFetch('not a url'), /invalid URL/);
});

after(() => {
  globalThis.fetch = originalFetch;
});
