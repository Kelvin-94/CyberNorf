import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  SIGNATURE_TOLERANCE_SECONDS,
  agentSigningKey,
  checkAgentSignature,
  signAgentBody,
} from './agent-signature';

const CREDENTIAL = 'cna_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const OTHER_CREDENTIAL = 'cna_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const BODY = '{"hostname":"kelvins-imac","checks":[]}';
const NOW = new Date('2026-11-09T12:00:00.000Z');
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);

test('a signature verifies only for the credential and bytes it was made for', () => {
  const signature = signAgentBody(CREDENTIAL, NOW_SECONDS, BODY);

  assert.deepEqual(
    checkAgentSignature({
      credential: CREDENTIAL,
      rawBody: BODY,
      signature,
      timestamp: String(NOW_SECONDS),
      now: NOW,
    }),
    { status: 'valid', timestamp: NOW_SECONDS },
  );

  // A different key, or a single changed byte, is a mismatch.
  assert.equal(
    checkAgentSignature({
      credential: OTHER_CREDENTIAL,
      rawBody: BODY,
      signature,
      timestamp: String(NOW_SECONDS),
      now: NOW,
    }).status,
    'invalid',
  );
  assert.deepEqual(
    checkAgentSignature({
      credential: CREDENTIAL,
      rawBody: `${BODY} `,
      signature,
      timestamp: String(NOW_SECONDS),
      now: NOW,
    }),
    { status: 'invalid', reason: 'mismatch' },
  );
});

test('the signing key changes when the credential rotates', () => {
  assert.notDeepEqual(agentSigningKey(CREDENTIAL), agentSigningKey(OTHER_CREDENTIAL));
});

test('a signature outside the tolerance window is rejected as stale', () => {
  const oldSeconds = NOW_SECONDS - SIGNATURE_TOLERANCE_SECONDS - 1;
  const signature = signAgentBody(CREDENTIAL, oldSeconds, BODY);

  assert.deepEqual(
    checkAgentSignature({
      credential: CREDENTIAL,
      rawBody: BODY,
      signature,
      timestamp: String(oldSeconds),
      now: NOW,
    }),
    { status: 'invalid', reason: 'stale' },
  );

  const futureSeconds = NOW_SECONDS + SIGNATURE_TOLERANCE_SECONDS + 1;
  assert.equal(
    checkAgentSignature({
      credential: CREDENTIAL,
      rawBody: BODY,
      signature: signAgentBody(CREDENTIAL, futureSeconds, BODY),
      timestamp: String(futureSeconds),
      now: NOW,
    }).status,
    'invalid',
  );
});

test('absent and malformed signatures are distinguishable', () => {
  assert.deepEqual(
    checkAgentSignature({
      credential: CREDENTIAL,
      rawBody: BODY,
      signature: null,
      timestamp: null,
      now: NOW,
    }),
    { status: 'absent' },
  );

  // A timestamp without a signature is not "unsigned": it is a broken attempt.
  assert.deepEqual(
    checkAgentSignature({
      credential: CREDENTIAL,
      rawBody: BODY,
      signature: null,
      timestamp: String(NOW_SECONDS),
      now: NOW,
    }),
    { status: 'invalid', reason: 'malformed' },
  );

  for (const signature of ['deadbeef', 'sha256=zz', `md5=${'a'.repeat(32)}`]) {
    assert.deepEqual(
      checkAgentSignature({
        credential: CREDENTIAL,
        rawBody: BODY,
        signature,
        timestamp: String(NOW_SECONDS),
        now: NOW,
      }),
      { status: 'invalid', reason: 'malformed' },
    );
  }
});
