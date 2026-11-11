import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  IndicatorFormatError,
  defang,
  inferIndicatorType,
  normalizeIndicator,
} from './indicators.ts';

function normalized(type: string, value: string): { type: string; value: string } {
  const result = normalizeIndicator({ type: type as never, value });
  return { type: result.type, value: result.value };
}

test('domains collapse to lower case and lose a trailing root dot', () => {
  assert.deepEqual(normalized('DOMAIN', 'EVIL.example.'), {
    type: 'DOMAIN',
    value: 'evil.example',
  });
  assert.deepEqual(normalized('DOMAIN', '  evil.example  '), {
    type: 'DOMAIN',
    value: 'evil.example',
  });
});

test('a wildcard domain keeps the part that can be matched', () => {
  assert.deepEqual(normalized('DOMAIN', '*.evil.example'), {
    type: 'DOMAIN',
    value: 'evil.example',
  });
});

test('defanged values are refanged before storage', () => {
  assert.deepEqual(normalized('DOMAIN', 'evil[.]example'), {
    type: 'DOMAIN',
    value: 'evil.example',
  });
  assert.deepEqual(normalized('URL', 'hxxps://evil[.]example/path'), {
    type: 'URL',
    value: 'https://evil.example/path',
  });
});

test('an IPv4-mapped IPv6 address collapses to IPv4 so one host is one indicator', () => {
  assert.deepEqual(normalized('IPV6', '::ffff:8.8.8.8'), { type: 'IPV4', value: '8.8.8.8' });
  assert.deepEqual(normalized('IPV4', '8.8.8.8'), { type: 'IPV4', value: '8.8.8.8' });
});

test('IPv6 is lower-cased but not otherwise rewritten', () => {
  assert.deepEqual(normalized('IPV6', '2001:DB8::1'), { type: 'IPV6', value: '2001:db8::1' });
});

test('a URL keeps its path case and drops the fragment', () => {
  assert.deepEqual(normalized('URL', 'https://evil.example/Path/To?q=1#frag'), {
    type: 'URL',
    value: 'https://evil.example/Path/To?q=1',
  });
});

test('hashes are lower-cased regardless of how they were pasted', () => {
  const sha = 'A'.repeat(64);
  assert.deepEqual(normalized('SHA256', sha), { type: 'SHA256', value: 'a'.repeat(64) });
  const md5 = 'B'.repeat(32);
  assert.deepEqual(normalized('MD5', md5), { type: 'MD5', value: 'b'.repeat(32) });
});

test('an email normalises its domain but not its local part case-sensitive rules', () => {
  assert.deepEqual(normalized('EMAIL', 'Analyst@Evil.Example'), {
    type: 'EMAIL',
    value: 'analyst@evil.example',
  });
});

test('trailing punctuation copied from prose is stripped', () => {
  assert.deepEqual(normalized('DOMAIN', 'evil.example,'), {
    type: 'DOMAIN',
    value: 'evil.example',
  });
  assert.deepEqual(normalized('DOMAIN', '`evil.example`'), {
    type: 'DOMAIN',
    value: 'evil.example',
  });
});

test('the original spelling is preserved for display when it differs', () => {
  const result = normalizeIndicator({ type: 'DOMAIN', value: 'EVIL.example' });
  assert.equal(result.value, 'evil.example');
  assert.equal(result.displayValue, 'EVIL.example');

  const identical = normalizeIndicator({ type: 'DOMAIN', value: 'evil.example' });
  assert.equal(identical.displayValue, null);
});

test('type is inferred when the caller does not supply one', () => {
  assert.equal(inferIndicatorType('8.8.8.8'), 'IPV4');
  assert.equal(inferIndicatorType('2001:db8::1'), 'IPV6');
  assert.equal(inferIndicatorType('a'.repeat(64)), 'SHA256');
  assert.equal(inferIndicatorType('b'.repeat(32)), 'MD5');
  assert.equal(inferIndicatorType('https://evil.example/x'), 'URL');
  assert.equal(inferIndicatorType('evil.example'), 'DOMAIN');
  assert.equal(inferIndicatorType('analyst@evil.example'), 'EMAIL');
});

test('a hash is inferred as a hash, never as a domain or an address', () => {
  // A 64-character hex string is a valid DNS label syntactically, so ordering
  // matters: the more specific type has to win.
  assert.equal(normalizeIndicator({ value: 'f'.repeat(64) }).type, 'SHA256');
});

test('values that cannot be matched are refused with a message naming the problem', () => {
  assert.throws(
    () => normalizeIndicator({ type: 'DOMAIN', value: 'localhost' }),
    IndicatorFormatError,
  );
  assert.throws(
    () => normalizeIndicator({ type: 'DOMAIN', value: 'not a domain' }),
    IndicatorFormatError,
  );
  assert.throws(
    () => normalizeIndicator({ type: 'IPV4', value: '999.1.1.1' }),
    IndicatorFormatError,
  );
  assert.throws(
    () => normalizeIndicator({ type: 'URL', value: 'evil.example/no-scheme' }),
    IndicatorFormatError,
  );
  assert.throws(
    () => normalizeIndicator({ type: 'URL', value: 'ftp://evil.example' }),
    IndicatorFormatError,
  );
  assert.throws(() => normalizeIndicator({ type: 'SHA256', value: 'short' }), IndicatorFormatError);
  assert.throws(() => normalizeIndicator({ value: '' }), IndicatorFormatError);
  assert.throws(() => normalizeIndicator({ value: 'just some words here' }), IndicatorFormatError);
});

test('an over-long value is refused instead of being truncated', () => {
  assert.throws(
    () => normalizeIndicator({ type: 'DOMAIN', value: `${'a'.repeat(300)}.example` }),
    IndicatorFormatError,
  );
});

test('defang produces a value that cannot be clicked', () => {
  assert.equal(defang('https://evil.example/x'), 'hxxps://evil[.]example/x');
  assert.equal(defang('evil.example'), 'evil[.]example');
});

test('normalisation is idempotent', () => {
  for (const [type, value] of [
    ['DOMAIN', 'EVIL.example.'],
    ['URL', 'https://evil.example/A?b=1#c'],
    ['SHA256', 'A'.repeat(64)],
    ['EMAIL', 'Analyst@Evil.Example'],
  ] as const) {
    const once = normalizeIndicator({ type, value });
    const twice = normalizeIndicator({ type: once.type, value: once.value });
    assert.equal(twice.value, once.value, `${type} changed on a second pass`);
  }
});
