import assert from 'node:assert/strict';
import { test } from 'node:test';
import { REDACTED, redactError, redactString, redactValue } from '@/server/security/redaction';

/**
 * Credential-shaped strings are assembled at runtime. Committing the literal
 * forms would make the repository's own secret scanner (correctly) flag this
 * fixture file and would train reviewers to ignore its output.
 */
const fixture = (...parts: string[]) => parts.join('');

test('removes bearer credentials but keeps the scheme visible', () => {
  const credential = fixture('cnk_', 'live_', '9f8e7d6c5b4a3210');
  const redacted = redactString(`request failed: Authorization: Bearer ${credential}`);
  assert.ok(!redacted.includes(credential));
  assert.match(redacted, /Authorization: \[redacted\]/);
});

test('removes credentials carried in query strings', () => {
  const redacted = redactString(
    'GET https://api.example.test/hook?token=abc123def456&signature=deadbeef&page=2',
  );
  assert.ok(!redacted.includes('abc123def456'));
  assert.ok(!redacted.includes('deadbeef'));
  // Non-credential parameters survive for diagnosability.
  assert.match(redacted, /page=2/);
});

test('redacts assignment-style secrets while keeping the field name', () => {
  const redacted = redactString(
    'body={"password":"hunter2hunter2","client_secret": "s3cr3t-value","api_key=abcd1234"}',
  );
  assert.ok(!redacted.includes('hunter2hunter2'));
  assert.ok(!redacted.includes('s3cr3t-value'));
  assert.ok(!redacted.includes('abcd1234'));
  assert.match(redacted, /"password":\[redacted\]/);
});

test('redacts well-known credential formats', () => {
  const inputs = [
    fixture('ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'),
    fixture('github_pat_', '11ABCDEFG0123456789_abcdefghijklmnop'),
    fixture('AKIA', 'IOSFODNN7EXAMPLE'),
    [
      'eyJhbGciOiJIUzI1NiJ9',
      'eyJzdWIiOiIxMjM0NTY3ODkwIn0',
      'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    ].join('.'),
    fixture('xoxb-', '123456789012-abcdefghijkl'),
  ];

  for (const secret of inputs) {
    const redacted = redactString(`provider rejected credential ${secret} for request`);
    assert.ok(!redacted.includes(secret), `expected ${secret.slice(0, 12)}… to be removed`);
    assert.match(redacted, /\[redacted\]/);
  }
});

test('redacts an entire PEM private key block', () => {
  const key = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz',
    'qwertyuiopasdfghjklzxcvbnm0987654321',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');

  const redacted = redactString(`handshake failed with key:\n${key}\nafter`);
  assert.ok(!redacted.includes('MIIEowIBAAKCAQEA'));
  assert.ok(!redacted.includes('BEGIN RSA PRIVATE KEY'));
  assert.ok(!redacted.includes('END RSA PRIVATE KEY'));
  assert.match(redacted, /after/);
});

test('does not redact ordinary text that merely mentions a sensitive word', () => {
  const message = 'The token budget is 10 and the password policy requires 12 characters.';
  assert.equal(redactString(message), message);
});

test('deep-copies objects, redacting secret fields by exact name', () => {
  const input = {
    outcome: 'failed',
    password: 'hunter2hunter2',
    nested: {
      webhookSecret: fixture('whsec_', 'abcdef123456'),
      apiKey: fixture('cnk_', 'abcdef'),
      note: 'rotated token via console',
    },
    attempts: 3,
  };

  const redacted = redactValue(input) as Record<string, unknown>;
  assert.equal(redacted.outcome, 'failed');
  assert.equal(redacted.password, REDACTED);
  const nested = redacted.nested as Record<string, unknown>;
  assert.equal(nested.webhookSecret, REDACTED);
  assert.equal(nested.apiKey, REDACTED);
  assert.equal(nested.note, 'rotated token via console');
  assert.equal(redacted.attempts, 3);

  // The caller's object is untouched: redaction must not corrupt the value that
  // is still being used by the request that is logging it.
  assert.equal(input.password, 'hunter2hunter2');
});

test('bounds depth and entry count so a hostile payload cannot stall logging', () => {
  let deep: Record<string, unknown> = { value: 'leaf' };
  for (let index = 0; index < 20; index += 1) {
    deep = { nested: deep };
  }

  const redacted = redactValue(deep) as Record<string, unknown>;
  let cursor: unknown = redacted;
  let depth = 0;
  while (cursor && typeof cursor === 'object' && 'nested' in cursor) {
    cursor = (cursor as Record<string, unknown>).nested;
    depth += 1;
  }
  assert.ok(depth <= 6);

  const wide = Object.fromEntries(
    Array.from({ length: 250 }, (_, index) => [`field${index}`, `value${index}`]),
  );
  const bounded = redactValue(wide) as Record<string, unknown>;
  assert.ok(Object.keys(bounded).length <= 100);
});

test('drops values JSON cannot represent instead of failing the audit write', () => {
  // A class instance with an enumerable `constructor` (Prisma's Decimal is one)
  // used to smuggle a function into audit metadata, which Prisma then refused
  // to serialise. The redactor must guarantee a JSON-safe result.
  class Money {
    constructor(public amount: number) {}
  }

  const redacted = redactValue({
    cvssScore: 7.5,
    nested: { fn: () => 'nope', symbol: Symbol('nope'), keep: 'value' },
    list: [() => 'nope', 'kept'],
    instance: new Money(3),
  }) as Record<string, unknown>;

  const nested = redacted.nested as Record<string, unknown>;
  assert.equal('fn' in nested, false);
  assert.equal('symbol' in nested, false);
  assert.equal(nested.keep, 'value');
  assert.deepEqual(redacted.list, ['kept']);
  assert.equal(redacted.cvssScore, 7.5);
  // The whole value survives a JSON round trip unchanged.
  assert.deepEqual(JSON.parse(JSON.stringify(redacted)), redacted);
});

test('serialises errors without leaking credentials', () => {
  const credential = fixture('sk_', 'live_', 'abcdef1234567890');
  const error = new Error(`upstream rejected Authorization: Bearer ${credential}`);
  const serialised = redactError(error);
  assert.match(serialised, /^Error: /);
  assert.ok(!serialised.includes(credential));

  assert.equal(redactError(undefined), 'unknown error');
  assert.equal(redactError('password=supersecretvalue'), 'password=[redacted]');
});
