import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { badRequest } from '@/server/errors';

/**
 * Outbound webhook safety.
 *
 * The server makes a request to a URL an operator typed, which is exactly the
 * shape of a server-side request forgery. Two defenses apply: the destination
 * must be an absolute https URL with no embedded credentials, and it must not
 * resolve to a loopback, private, link-local, or otherwise non-routable
 * address. A deployment that genuinely needs an internal collector can opt in
 * with NOTIFY_ALLOW_PRIVATE_WEBHOOKS=true, which is a deliberate trust decision
 * recorded in the deployment notes.
 *
 * The addresses returned here are the ones the sender dials. Handing them to
 * the socket's resolver removes the second lookup that a DNS-rebinding attack
 * relies on, and redirects are never followed.
 */

export function allowPrivateWebhooks(): boolean {
  return process.env.NOTIFY_ALLOW_PRIVATE_WEBHOOKS === 'true';
}

const V4_PRIVATE_BLOCKS: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

function v4ToInt(address: string): number | null {
  const parts = address.split('.');
  if (parts.length !== 4) {
    return null;
  }
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return null;
    }
    const octet = Number(part);
    if (octet > 255) {
      return null;
    }
    value = value * 256 + octet;
  }
  return value;
}

function isPrivateV4(address: string): boolean {
  const value = v4ToInt(address);
  if (value === null) {
    return true;
  }
  return V4_PRIVATE_BLOCKS.some(([block, bits]) => {
    const base = v4ToInt(block);
    if (base === null) {
      return false;
    }
    const size = 2 ** (32 - bits);
    return value >= base && value < base + size;
  });
}

function isPrivateV6(address: string): boolean {
  const normalized = address.toLowerCase().split('%')[0] ?? address.toLowerCase();

  // IPv4-mapped (::ffff:10.0.0.1) and IPv4-compatible forms must be judged by
  // the address they carry, otherwise a v4 loopback hides inside a v6 literal.
  const mapped = normalized.match(/(?:::ffff:|::)(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped?.[1]) {
    return isPrivateV4(mapped[1]);
  }

  if (normalized === '::' || normalized === '::1') {
    return true;
  }
  if (
    normalized.startsWith('fe8') ||
    normalized.startsWith('fe9') ||
    normalized.startsWith('fea') ||
    normalized.startsWith('feb')
  ) {
    return true; // link-local fe80::/10
  }
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return true; // unique local fc00::/7
  }
  if (normalized.startsWith('ff')) {
    return true; // multicast
  }
  return false;
}

/** True for loopback, private, link-local, multicast, and documentation ranges. */
export function isPrivateAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    return isPrivateV4(address);
  }
  if (family === 6) {
    return isPrivateV6(address);
  }
  // Anything that is not a literal address cannot be judged, so treat it as
  // unsafe instead of guessing.
  return true;
}

export interface ResolvedWebhookTarget {
  url: URL;
  /**
   * Addresses that passed the policy check, in resolver order. The sender dials
   * one of these directly; an empty list means "let the socket resolve" and is
   * only possible when private destinations were explicitly allowed.
   */
  addresses: Array<{ address: string; family: number }>;
}

function hostOf(url: URL): string {
  return url.hostname.replace(/^\[/, '').replace(/\]$/, '');
}

/**
 * Validates a webhook destination and resolves the addresses that may be
 * dialled. Throws a BAD_REQUEST AppError with an operator-facing reason on any
 * violation.
 */
export async function resolveWebhookTarget(raw: string): Promise<ResolvedWebhookTarget> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw badRequest('The webhook URL is not a valid absolute URL.');
  }

  const isProduction = process.env.NODE_ENV === 'production';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && !isProduction)) {
    throw badRequest('Webhook URLs must use https.');
  }
  if (url.username || url.password) {
    throw badRequest('Webhook URLs must not embed credentials.');
  }
  if (!url.hostname) {
    throw badRequest('The webhook URL must include a host.');
  }

  const host = hostOf(url);
  const literal = isIP(host);
  if (literal) {
    if (!allowPrivateWebhooks() && isPrivateAddress(host)) {
      throw badRequest('Webhook URLs must not target loopback, private, or reserved addresses.');
    }
    return { url, addresses: [{ address: host, family: literal }] };
  }

  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    if (allowPrivateWebhooks()) {
      // The operator opted into internal destinations, so fall back to letting
      // the socket resolve rather than refusing a name only their resolver knows.
      return { url, addresses: [] };
    }
    throw badRequest('The webhook host could not be resolved.');
  }
  if (
    !allowPrivateWebhooks() &&
    (addresses.length === 0 || addresses.some((record) => isPrivateAddress(record.address)))
  ) {
    throw badRequest('Webhook URLs must not resolve to loopback, private, or reserved addresses.');
  }

  return { url, addresses };
}

/** Validates a webhook destination and returns the parsed URL. */
export async function assertSafeWebhookUrl(raw: string): Promise<URL> {
  return (await resolveWebhookTarget(raw)).url;
}
