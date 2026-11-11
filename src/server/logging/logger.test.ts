import assert from 'node:assert/strict';
import { test } from 'node:test';
import { REDACTED } from '@/server/security/redaction';
import { createLogger, resolveLogLevel } from './logger.ts';

/** Collects emitted lines and parses them, failing loudly on invalid JSON. */
function collector() {
  const lines: string[] = [];
  return {
    lines,
    sink: (line: string) => {
      lines.push(line);
    },
    records(): Record<string, unknown>[] {
      return lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    },
    last(): Record<string, unknown> {
      const record = this.records().at(-1);
      assert.ok(record, 'no log line was emitted');
      return record;
    },
  };
}

const FAKE_GITHUB_TOKEN = `ghp_${'a'.repeat(36)}`;

test('a record is one JSON line with stable fields', () => {
  const output = collector();
  const logger = createLogger({ level: 'info', sink: output.sink });

  logger.info('asset.created', { organizationId: 'org_1', assetId: 'asset_1' });

  assert.equal(output.lines.length, 1);
  assert.ok(!output.lines[0]?.includes('\n'), 'a record must not span lines');

  const record = output.last();
  assert.equal(record.level, 'info');
  assert.equal(record.msg, 'asset.created');
  assert.equal(record.service, 'cybernorf');
  assert.equal(record.organizationId, 'org_1');
  assert.equal(record.assetId, 'asset_1');
  assert.ok(typeof record.time === 'string');
  assert.ok(!Number.isNaN(Date.parse(String(record.time))), 'time must be an ISO timestamp');
});

test('the level threshold suppresses lower levels', () => {
  const output = collector();
  const logger = createLogger({ level: 'warn', sink: output.sink });

  logger.debug('debug.line');
  logger.info('info.line');
  logger.warn('warn.line');
  logger.error('error.line');

  assert.deepEqual(
    output.records().map((record) => record.msg),
    ['warn.line', 'error.line'],
  );
});

test('secret-named keys are redacted at any depth', () => {
  const output = collector();
  const logger = createLogger({ level: 'info', sink: output.sink });

  logger.info('integration.configured', {
    provider: 'acme',
    credentials: { clientSecret: 'super-secret-value', token: 'plain-token' },
    nested: [{ password: 'hunter2' }],
  });

  const serialised = JSON.stringify(output.last());
  for (const secret of ['super-secret-value', 'plain-token', 'hunter2']) {
    assert.ok(!serialised.includes(secret), `log line leaked ${secret}`);
  }
  assert.ok(serialised.includes(REDACTED));
});

test('credential-shaped strings are redacted even under innocent keys', () => {
  const output = collector();
  const logger = createLogger({ level: 'info', sink: output.sink });

  logger.info('provider.error', { detail: `request failed with ${FAKE_GITHUB_TOKEN}` });
  logger.info(`authorization header was Bearer ${FAKE_GITHUB_TOKEN}`);

  const serialised = JSON.stringify(output.records());
  assert.ok(!serialised.includes(FAKE_GITHUB_TOKEN), 'log line leaked a token shape');
});

test('an Error is serialised with name and redacted message, stack only at error level', () => {
  const output = collector();
  const logger = createLogger({ level: 'info', sink: output.sink });

  logger.error('request.unhandled_error', {
    requestId: 'req_1',
    error: new TypeError(`could not reach provider with ${FAKE_GITHUB_TOKEN}`),
  });
  logger.warn('request.slow', { error: new Error('slow') });

  const [errorRecord, warnRecord] = output.records();
  const error = errorRecord?.error as Record<string, unknown>;
  const warn = warnRecord?.error as Record<string, unknown>;

  assert.equal(error.name, 'TypeError');
  assert.ok(String(error.message).includes('[redacted]'));
  assert.ok(String(error.message).includes('could not reach provider'));
  assert.ok(typeof error.stack === 'string', 'error level should carry a stack');

  assert.equal(warn.name, 'Error');
  assert.equal(warn.stack, undefined, 'non-error levels should omit the stack');
});

test('child loggers repeat their bindings', () => {
  const output = collector();
  const logger = createLogger({ level: 'info', sink: output.sink });
  const request = logger.child({ requestId: 'req_42', route: '/api/v1/me' });

  request.info('request.completed', { status: 200 });
  request.warn('request.retried');

  const records = output.records();
  assert.equal(records.length, 2);
  for (const record of records) {
    assert.equal(record.requestId, 'req_42');
    assert.equal(record.route, '/api/v1/me');
  }
});

test('a circular object does not prevent the record from being written', () => {
  const output = collector();
  const logger = createLogger({ level: 'info', sink: output.sink });
  const circular: Record<string, unknown> = { name: 'loop' };
  circular.self = circular;

  logger.info('circular.payload', { circular });

  assert.equal(output.lines.length, 1);
  assert.equal(output.last().msg, 'circular.payload');
});

test('a failing sink never propagates to the caller', () => {
  const logger = createLogger({
    level: 'info',
    sink: () => {
      throw new Error('collector unavailable');
    },
  });

  assert.doesNotThrow(() => {
    logger.error('request.unhandled_error', { error: new Error('boom') });
  });
});

test('LOG_LEVEL parsing falls back for unknown values', () => {
  assert.equal(resolveLogLevel('debug'), 'debug');
  assert.equal(resolveLogLevel(' WARN '), 'warn');
  assert.equal(resolveLogLevel('verbose'), 'info');
  assert.equal(resolveLogLevel(undefined), 'info');
});
