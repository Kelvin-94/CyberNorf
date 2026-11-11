import { isIP } from 'node:net';

/**
 * Normalisation and classification of indicators of compromise.
 *
 * The whole value of an indicator is that two sources writing the same thing
 * differently collapse into one record. `EVIL.example` and `evil.example` are the
 * same domain; `8.8.8.8` and `::ffff:8.8.8.8` are the same address; a hash
 * pasted from a report in upper case is the same hash. Everything here exists to
 * make that collapse deterministic, and to reject values that cannot be matched
 * against telemetry at all.
 *
 * Normalisation is deliberately *not* applied to the display value: an analyst
 * reading a report needs to see the value as the source published it.
 */

export type IndicatorType = 'IPV4' | 'IPV6' | 'DOMAIN' | 'URL' | 'SHA256' | 'MD5' | 'EMAIL';

export const INDICATOR_TYPES: readonly IndicatorType[] = [
  'IPV4',
  'IPV6',
  'DOMAIN',
  'URL',
  'SHA256',
  'MD5',
  'EMAIL',
];

export class IndicatorFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IndicatorFormatError';
  }
}

/** Longest value we store; the database constraint uses the same bound. */
export const MAX_INDICATOR_LENGTH = 2048;

const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MD5 = /^[0-9a-f]{32}$/;

/**
 * Removes the surrounding syntax an analyst copies out of a report or a chat
 * message: backticks, angle brackets, trailing punctuation, and the `hxxp`
 * convention used to keep a link from being clickable.
 */
function unwrap(raw: string): string {
  let value = raw.trim();
  // Repeatedly strip one layer of quoting characters from either end.
  for (let pass = 0; pass < 3; pass += 1) {
    const before = value;
    value = value.replace(/^[`'"<([{]+/, '').replace(/[`'"\])}>.,;:]+$/, '');
    if (value === before) {
      break;
    }
  }
  return value.trim();
}

/**
 * Reverses the defanging convention: `hxxp://`, `example[.]com`, `a[.]b`.
 * Defanged text is what a report contains precisely so it cannot be clicked, so
 * refusing it would mean an analyst re-types every indicator by hand.
 */
function refang(value: string): string {
  return value
    .replace(/hxxps?:\/\//gi, (match) => (match.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://'))
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/hxxp/gi, 'http');
}

function normalizeDomain(input: string): string {
  // A trailing dot is the DNS root and means the same name.
  const value = input.toLowerCase().replace(/\.$/, '');
  if (value.length === 0 || value.length > 253) {
    throw new IndicatorFormatError('Domain is empty or longer than 253 characters.');
  }
  // A wildcard prefix is accepted for a feed that reports subdomains, but it is
  // normalised to the part that can actually be matched.
  const bare = value.startsWith('*.') ? value.slice(2) : value;
  const labels = bare.split('.');
  if (labels.length < 2) {
    throw new IndicatorFormatError('Domain must have at least two labels, for example example.com.');
  }
  for (const label of labels) {
    if (!DOMAIN_LABEL.test(label)) {
      throw new IndicatorFormatError(`"${label}" is not a valid domain label.`);
    }
  }
  if (!TLD.test(labels[labels.length - 1] ?? '')) {
    throw new IndicatorFormatError('Domain does not end in a valid top-level domain.');
  }
  return bare;
}

function normalizeIp(input: string): { type: 'IPV4' | 'IPV6'; value: string } {
  const family = isIP(input);
  if (family === 0) {
    throw new IndicatorFormatError('Not a valid IPv4 or IPv6 address.');
  }
  // `isIP` accepts IPv4-mapped IPv6. Collapsing it keeps one address from being
  // stored twice under two spellings, which would halve the match rate.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(input);
  if (family === 6 && mapped?.[1] && isIP(mapped[1]) === 4) {
    return { type: 'IPV4', value: mapped[1] };
  }
  return { type: family === 4 ? 'IPV4' : 'IPV6', value: input.toLowerCase() };
}

function normalizeUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new IndicatorFormatError('URL must be absolute, including the scheme.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new IndicatorFormatError('URL must use http:// or https://.');
  }
  if (!url.hostname) {
    throw new IndicatorFormatError('URL has no host.');
  }
  // The scheme and host are case-insensitive; a path is not, so it is preserved
  // exactly. The fragment is dropped because it never reaches a server, and a
  // differing fragment would otherwise create a second copy of one URL.
  url.hash = '';
  const normalised = url.toString();
  if (normalised.length > MAX_INDICATOR_LENGTH) {
    throw new IndicatorFormatError('URL is too long.');
  }
  return normalised;
}

function normalizeEmail(input: string): string {
  const value = input.toLowerCase();
  const at = value.lastIndexOf('@');
  if (at <= 0 || at === value.length - 1) {
    throw new IndicatorFormatError('Email must have a local part and a domain.');
  }
  // The domain follows the same rules as a domain indicator, so
  // `analyst@Example.COM` and `analyst@example.com` are one record.
  const domain = normalizeDomain(value.slice(at + 1));
  const local = value.slice(0, at);
  if (!/^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) {
    throw new IndicatorFormatError('Email local part contains unsupported characters.');
  }
  return `${local}@${domain}`;
}

export interface NormalizedIndicator {
  type: IndicatorType;
  value: string;
  /** The value as it was supplied, for display. Null when it is identical. */
  displayValue: string | null;
}

/**
 * Normalises a value for the given type, or infers the type when none is given.
 *
 * Inference exists because an analyst pasting from a report often does not know
 * (or care) whether the platform calls it DOMAIN or HOSTNAME. It is ordered from
 * most to least specific so an ambiguous string lands in the narrowest bucket:
 * a 64-character hex string is a hash before it is anything else.
 */
export function normalizeIndicator(input: {
  type?: IndicatorType | undefined;
  value: string;
}): NormalizedIndicator {
  const unfanged = refang(unwrap(input.value));
  if (unfanged.length === 0) {
    throw new IndicatorFormatError('Indicator value is empty.');
  }
  if (unfanged.length > MAX_INDICATOR_LENGTH) {
    throw new IndicatorFormatError(`Indicator value is longer than ${MAX_INDICATOR_LENGTH} characters.`);
  }

  const resolved = input.type ?? inferIndicatorType(unfanged);
  if (!resolved) {
    throw new IndicatorFormatError(
      'Could not tell what kind of indicator this is: provide a type, or a value that is an IP address, domain, URL, email, or MD5/SHA-256 hash.',
    );
  }

  let value: string;
  let type: IndicatorType = resolved;

  switch (resolved) {
    case 'IPV4':
    case 'IPV6': {
      const parsed = normalizeIp(unfanged);
      // A caller that says IPV6 but supplies an IPv4-mapped address gets the
      // collapsed type, because that is what will be matched.
      type = parsed.type;
      value = parsed.value;
      break;
    }
    case 'DOMAIN':
      value = normalizeDomain(unfanged);
      break;
    case 'URL':
      value = normalizeUrl(unfanged);
      break;
    case 'EMAIL':
      value = normalizeEmail(unfanged);
      break;
    case 'SHA256':
      value = unfanged.toLowerCase();
      if (!SHA256.test(value)) {
        throw new IndicatorFormatError('SHA-256 must be 64 hexadecimal characters.');
      }
      break;
    case 'MD5':
      value = unfanged.toLowerCase();
      if (!MD5.test(value)) {
        throw new IndicatorFormatError('MD5 must be 32 hexadecimal characters.');
      }
      break;
    default: {
      // Exhaustiveness: adding a type above without a case here is a build error.
      const exhaustive: never = resolved;
      throw new IndicatorFormatError(`Unsupported indicator type: ${String(exhaustive)}`);
    }
  }

  return {
    type,
    value,
    displayValue: unfanged === value || input.value.trim() === value ? null : unfanged,
  };
}

/** Guesses the type of a value, or returns null when nothing fits. */
export function inferIndicatorType(raw: string): IndicatorType | null {
  const value = refang(unwrap(raw));

  if (SHA256.test(value.toLowerCase())) {
    return 'SHA256';
  }
  if (MD5.test(value.toLowerCase())) {
    return 'MD5';
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    return 'URL';
  }
  if (isIP(value) !== 0) {
    return isIP(value) === 4 ? 'IPV4' : 'IPV6';
  }
  // Only call something an email when it has both parts and a domain-like
  // suffix; otherwise `C:\Users\name` style strings would look like emails.
  if (value.includes('@') && !value.includes(' ')) {
    const domain = value.slice(value.lastIndexOf('@') + 1);
    try {
      normalizeDomain(domain);
      return 'EMAIL';
    } catch {
      return null;
    }
  }
  try {
    normalizeDomain(value);
    return 'DOMAIN';
  } catch {
    return null;
  }
}

/**
 * Writes a value back in the defanged form used in reports and chat, so an
 * indicator can be pasted somewhere it must not become a live link.
 */
export function defang(value: string): string {
  return value.replace(/\./g, '[.]').replace(/^http/i, 'hxxp');
}

/** Human label for a type, used in messages and exports. */
export const INDICATOR_TYPE_LABELS: Record<IndicatorType, string> = {
  IPV4: 'IPv4 address',
  IPV6: 'IPv6 address',
  DOMAIN: 'Domain',
  URL: 'URL',
  SHA256: 'SHA-256 hash',
  MD5: 'MD5 hash',
  EMAIL: 'Email address',
};
