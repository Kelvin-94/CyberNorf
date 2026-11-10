/**
 * Bounds the OpenID Connect discovery request Better Auth makes while it
 * initialises the generic OAuth plugin.
 *
 * The plugin builds its provider list during `init` and fetches
 * `<issuer>/.well-known/openid-configuration` there without a timeout; only the
 * retry performed on a later sign-in is bounded (10s). An identity provider that
 * accepts the connection but never answers would therefore hold the first auth
 * request open until the operating system gives up, which looks like a hung app.
 * The plugin exposes no option for that first fetch, so the bound is applied at
 * the fetch layer instead: a wrapper adds an abort signal to requests for
 * exactly the configured discovery URL and passes every other request through
 * untouched.
 *
 * The bound is combined with any signal the caller already holds instead of
 * replacing it: the HTTP client passes its own controller signal on every
 * request, and replacing that would break its cancellation. The five-second cap
 * therefore also applies to the plugin's sign-in retry, which is deliberately
 * fine — a provider that cannot answer discovery within five seconds is treated
 * as unavailable and retried on the next attempt.
 *
 * A timeout lands in the plugin's existing failure path: the provider is skipped
 * for now and kept pending, so passwords keep working and the next sign-in
 * retries discovery instead of failing closed forever.
 */

/** Discovery gives up after this long, at startup and on the sign-in retry. */
export const DISCOVERY_TIMEOUT_MS = 5_000;

/** Marks a fetch wrapper installed by this module and the URLs it bounds. */
const BOUNDED_URLS = Symbol.for('cybernorf.oidc.boundedDiscoveryUrls');

type BoundedFetch = typeof fetch & { [BOUNDED_URLS]?: Set<string> };

function canonicalUrl(value: string): string | null {
  try {
    return new URL(value).href;
  } catch {
    return null;
  }
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }
  return input instanceof URL ? input.href : input.url;
}

/**
 * Installs the wrapper once per process. Calling it again for another discovery
 * URL extends the existing wrapper rather than stacking a second one, so tests
 * and several auth instances cannot multiply the interception.
 */
export function boundDiscoveryFetch(
  discoveryUrl: string,
  timeoutMs: number = DISCOVERY_TIMEOUT_MS,
): void {
  const current = globalThis.fetch as BoundedFetch;
  const bounded = canonicalUrl(discoveryUrl);
  if (bounded === null) {
    throw new Error(`Cannot bound discovery for an invalid URL: ${discoveryUrl}`);
  }

  const existing = current[BOUNDED_URLS];
  if (existing) {
    existing.add(bounded);
    return;
  }

  const urls = new Set([bounded]);
  const wrapper = ((input: RequestInfo | URL, init?: RequestInit) => {
    if (urls.has(canonicalUrl(requestUrl(input)) ?? '')) {
      const bound = AbortSignal.timeout(timeoutMs);
      const signal = init?.signal ? AbortSignal.any([init.signal, bound]) : bound;
      return current(input, { ...init, signal });
    }
    return current(input, init);
  }) as BoundedFetch;
  wrapper[BOUNDED_URLS] = urls;
  globalThis.fetch = wrapper;
}
