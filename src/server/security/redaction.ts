/**
 * Last line of defence for secrets that would otherwise end up in a place they
 * must never reach: application logs, audit summaries, and audit metadata.
 *
 * This is deliberately conservative. Callers should not pass credentials here
 * in the first place; the module exists so that a mistake in one call site (a
 * provider error that echoes a token, an audit diff that includes a webhook
 * key, a debug string built from a request body) cannot turn into a durable
 * leak. Redaction is applied before an audit row is hashed, so the stored chain
 * covers exactly the redacted value and verification stays stable.
 */

export const REDACTED = '[redacted]';

const MAX_STRING_LENGTH = 8_000;
const MAX_DEPTH = 6;
const MAX_ENTRIES = 100;

/**
 * Object keys whose value is always a credential, matched exactly after
 * normalising case and separators. Suffix matching is avoided on purpose:
 * `tokenCount` or `keyFingerprint` are not secrets, and over-redacting audit
 * data destroys its evidentiary value.
 */
const SECRET_KEYS = new Set([
  'password',
  'passphrase',
  'currentpassword',
  'newpassword',
  'secret',
  'clientsecret',
  'apikey',
  'accesskey',
  'secretkey',
  'privatekey',
  'signingkey',
  'hmackey',
  'webhooksecret',
  'token',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'sessiontoken',
  'authtoken',
  'authorization',
  'cookie',
  'setcookie',
  'credential',
  'credentials',
  'bearer',
  'totpsecret',
  'backupcodes',
]);

/** Token shapes that identify a credential wherever they appear. */
const TOKEN_PATTERNS: RegExp[] = [
  // GitHub tokens, including fine-grained personal access tokens.
  /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
  // Stripe-style live/test keys.
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,255}\b/g,
  // Slack tokens and webhook URLs.
  /\bxox[abprs]-[A-Za-z0-9-]{10,255}\b/g,
  /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{10,255}/g,
  // AWS access key ids.
  /\bAKIA[0-9A-Z]{16}\b/g,
  // JSON Web Tokens (three base64url segments).
  /\beyJ[A-Za-z0-9_-]{5,512}\.[A-Za-z0-9_-]{5,512}\.[A-Za-z0-9_-]{5,512}\b/g,
];

/**
 * A complete `Authorization: Bearer …` header. The field name is preserved so
 * the log still shows which credential was rejected, but the scheme and value
 * are removed together; matching the scheme separately would leave a value
 * behind that the assignment rule then partially consumes.
 */
const AUTHORIZATION_HEADER_PATTERN =
  /\b(authorization\s*[:=]\s*)(?:(?:Bearer|Basic|Token)\s+)?[A-Za-z0-9._~+/=-]{8,512}/gi;

/** Standalone `Bearer …`, `Basic …`, and similar scheme credentials. */
const AUTH_SCHEME_PATTERN = /\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,512}/gi;

/** Credentials carried in a URL query string. */
const URL_CREDENTIAL_PATTERN =
  /([?&](?:token|key|secret|password|signature|sig|code|api[_-]?key|access[_-]?token)=)[^&\s#]{1,512}/gi;

/**
 * `password=hunter2`, `"client_secret": "…"`, `api_key: …`. The key prefix is
 * preserved so a redacted log line still shows which field was present.
 */
const ASSIGNMENT_PATTERN =
  /((?:password|passphrase|secret|client[_-]?secret|api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|signing[_-]?key|webhook[_-]?secret)\s*["']?\s*[:=]\s*)(?:"[^"\n]{1,512}"|'[^'\n]{1,512}'|[^\s,;&]{1,512})/gi;

function redactPemBlocks(input: string): string {
  let output = input;
  let searchFrom = 0;

  for (;;) {
    const begin = output.indexOf('-----BEGIN ', searchFrom);
    if (begin === -1) {
      return output;
    }
    const headerEnd = output.indexOf('-----', begin + 11);
    if (headerEnd === -1) {
      return output;
    }
    const header = output.slice(begin, headerEnd + 5);
    if (!header.includes('PRIVATE KEY')) {
      searchFrom = headerEnd + 5;
      continue;
    }
    const end = output.indexOf('-----END ', headerEnd);
    if (end === -1) {
      // Unterminated block: drop everything from the header onward. A partial
      // key is still key material.
      return `${output.slice(0, begin)}${REDACTED}`;
    }
    const endMarker = output.indexOf('-----', end + 9);
    const blockEnd = endMarker === -1 ? output.length : endMarker + 5;
    output = `${output.slice(0, begin)}${REDACTED}${output.slice(blockEnd)}`;
    searchFrom = begin + REDACTED.length;
  }
}

/**
 * Redacts credentials from a single string. Bounded to 8k characters so an
 * oversized value cannot turn logging into a CPU or memory problem.
 */
export function redactString(value: string): string {
  let output = value.length > MAX_STRING_LENGTH ? value.slice(0, MAX_STRING_LENGTH) : value;

  output = redactPemBlocks(output);
  output = output.replace(AUTHORIZATION_HEADER_PATTERN, `$1${REDACTED}`);
  output = output.replace(AUTH_SCHEME_PATTERN, `$1 ${REDACTED}`);
  for (const pattern of TOKEN_PATTERNS) {
    output = output.replace(pattern, REDACTED);
  }
  output = output.replace(URL_CREDENTIAL_PATTERN, `$1${REDACTED}`);
  output = output.replace(ASSIGNMENT_PATTERN, `$1${REDACTED}`);

  return output;
}

function isSecretKey(key: string): boolean {
  return SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z0-9]/g, ''));
}

/**
 * Deep-copies a JSON-like value with credential-bearing strings and fields
 * replaced. Arrays and objects are bounded so a pathological payload cannot
 * stall the caller, and the input is never mutated.
 */
export function redactValue(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') {
    return redactString(value);
  }
  // Audit metadata must stay JSON-serialisable. A function or symbol reaching
  // this point (for example a class instance exposing an enumerable
  // `constructor`) would otherwise be copied into the payload and make the
  // whole audit write fail, taking the user's mutation down with it.
  if (typeof value === 'function' || typeof value === 'symbol') {
    return undefined;
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (depth >= MAX_DEPTH) {
    return REDACTED;
  }
  if (Array.isArray(value)) {
    return (
      value
        .slice(0, MAX_ENTRIES)
        .map((entry) => redactValue(entry, depth + 1))
        // Mapping a dropped function would leave a hole that JSON renders as
        // `null`; removing it keeps the array meaningful after redaction.
        .filter((entry) => entry !== undefined)
    );
  }

  const output: Record<string, unknown> = {};
  let entries = 0;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (entries >= MAX_ENTRIES) {
      break;
    }
    entries += 1;
    if (isSecretKey(key)) {
      output[key] = REDACTED;
      continue;
    }
    if (entry === undefined) {
      continue;
    }
    const redacted = redactValue(entry, depth + 1);
    // Dropping the key rather than writing `undefined` keeps the result a
    // valid JSON value for Prisma.
    if (redacted === undefined) {
      continue;
    }
    output[key] = redacted;
  }
  return output;
}

/** Serialises an error for a log line without leaking credentials or payloads. */
export function redactError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.name}: ${redactString(error.message)}`;
  }
  if (typeof error === 'string') {
    return redactString(error);
  }
  return redactString(JSON.stringify(redactValue(error)) ?? 'unknown error');
}
