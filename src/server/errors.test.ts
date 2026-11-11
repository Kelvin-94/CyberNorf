import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AppError, toErrorResponse } from './errors.ts';

const FAKE_TOKEN = `ghp_${'b'.repeat(36)}`;

/** Captures what the application logger writes to stdout for one block. */
function captureStdout(): { lines: string[]; restore: () => void } {
  const original = process.stdout.write.bind(process.stdout);
  const lines: string[] = [];
  process.stdout.write = ((chunk: unknown) => {
    lines.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  return { lines, restore: () => (process.stdout.write = original) };
}

test('an unhandled error is logged once as structured JSON and redacted', async () => {
  const output = captureStdout();
  let response: Response;
  try {
    response = toErrorResponse(
      new Error(`upstream rejected the request with ${FAKE_TOKEN}`),
      'req_structured_1',
    );
  } finally {
    output.restore();
  }

  const records = output.lines
    .join('')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.equal(records.length, 1, 'exactly one log line should be written');

  const record = records[0];
  assert.equal(record?.level, 'error');
  assert.equal(record?.msg, 'request.unhandled_error');
  assert.equal(record?.requestId, 'req_structured_1');

  const error = record?.error as Record<string, unknown>;
  assert.equal(error.name, 'Error');
  assert.ok(String(error.message).includes('upstream rejected'));
  assert.ok(!JSON.stringify(record).includes(FAKE_TOKEN), 'the log line leaked a credential');

  // The caller gets a generic 500; the token must not travel in the response.
  assert.equal(response.status, 500);
  const body = await response.text();
  assert.ok(!body.includes(FAKE_TOKEN));
  assert.ok(body.includes('req_structured_1'), 'the request id must be returned for correlation');
});

test('a handled AppError is returned without logging', async () => {
  const output = captureStdout();
  let response: Response;
  try {
    response = toErrorResponse(new AppError(404, 'NOT_FOUND', 'Not found.'), 'req_2');
  } finally {
    output.restore();
  }

  assert.equal(response.status, 404);
  assert.equal(output.lines.length, 0, 'client errors are not application faults');
});
