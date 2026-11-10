import {
  request as httpRequest,
  type ClientRequest,
  type IncomingMessage,
  type RequestOptions,
} from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { LookupFunction } from 'node:net';

/**
 * Delivery transport for outbound webhooks.
 *
 * `fetch` resolves the hostname itself, immediately before connecting, which
 * re-opens the gap between validation and use: an attacker who controls the DNS
 * record can answer the first lookup with a public address and the second with
 * an internal one (DNS rebinding). This transport takes the addresses that were
 * validated and hands them to the socket's `lookup` hook, so the connection goes
 * to exactly one of them and the name is never resolved again.
 *
 * Host header and TLS SNI still come from the URL, so certificate validation and
 * virtual hosting behave normally. Redirects are not followed: a 3xx status is
 * returned as-is and the caller treats it as a failure, so the destination
 * cannot be bounced to a host the policy never saw.
 */

export interface PinnedAddress {
  address: string;
  family: number;
}

export interface PinnedPostOptions {
  headers: Record<string, string>;
  body: string;
  timeoutMs: number;
}

/** How many validated addresses one delivery may try before giving up. */
const MAX_ADDRESS_ATTEMPTS = 3;

export async function sendPinnedPost(
  url: URL,
  addresses: PinnedAddress[],
  options: PinnedPostOptions,
): Promise<number> {
  const candidates = addresses.slice(0, MAX_ADDRESS_ATTEMPTS);
  if (candidates.length === 0) {
    // Only reachable when private destinations were explicitly allowed and the
    // name is known to a resolver the process cannot query up front.
    return once(url, undefined, options);
  }

  let lastError: unknown = new Error('No address was available for the webhook host.');
  for (const candidate of candidates) {
    try {
      return await once(url, candidate, options);
    } catch (error) {
      // A dual-stack name can have an unreachable family; the next address is
      // still one the policy approved, so trying it does not widen the target.
      lastError = error;
    }
  }
  throw lastError;
}

/** Resolver that answers with the validated address for any name it is asked. */
function pinnedLookup(address: string, family: number): LookupFunction {
  return (_hostname, lookupOptions, callback) => {
    if (lookupOptions.all) {
      callback(null, [{ address, family }]);
      return;
    }
    callback(null, address, family);
  };
}

function once(
  url: URL,
  pinned: PinnedAddress | undefined,
  { headers, body, timeoutMs }: PinnedPostOptions,
): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const secure = url.protocol === 'https:';
    const requestOptions: RequestOptions = {
      hostname: url.hostname.replace(/^\[/, '').replace(/\]$/, ''),
      port: Number(url.port || (secure ? 443 : 80)),
      path: `${url.pathname}${url.search}`,
      method: 'POST',
      headers: { ...headers, 'content-length': String(Buffer.byteLength(body)) },
      // One connection per delivery: no pooled socket is reused for a
      // destination that was validated for a single event.
      agent: false,
    };
    if (pinned) {
      requestOptions.lookup = pinnedLookup(pinned.address, pinned.family === 6 ? 6 : 4);
    }

    const onResponse = (response: IncomingMessage): void => {
      clearTimeout(timer);
      // Only the status line matters; dropping the socket avoids buffering an
      // endpoint's error page into the delivery worker.
      response.on('error', () => undefined);
      response.destroy();
      resolve(response.statusCode ?? 0);
    };

    const request: ClientRequest = secure
      ? httpsRequest(requestOptions, onResponse)
      : httpRequest(requestOptions, onResponse);

    const timer = setTimeout(() => {
      request.destroy(new Error(`The endpoint did not answer within ${timeoutMs} ms.`));
    }, timeoutMs);
    timer.unref();

    request.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    request.end(body);
  });
}
