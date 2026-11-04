import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  attestationIssue,
  computePosture,
  emptyCounts,
  isAttested,
  postureBand,
  requiresEvidence,
} from './compliance.ts';

test('an all-implemented framework scores 100 and is READY', () => {
  const posture = computePosture([
    { status: 'IMPLEMENTED', weight: 3 },
    { status: 'IMPLEMENTED', weight: 1 },
  ]);
  assert.equal(posture.score, 100);
  assert.equal(posture.band, 'READY');
  assert.equal(posture.applicableWeight, 4);
  assert.equal(posture.total, 2);
});

test('partial coverage earns half credit and in-progress a quarter', () => {
  const posture = computePosture([
    { status: 'IMPLEMENTED', weight: 2 },
    { status: 'PARTIAL', weight: 2 },
    { status: 'IN_PROGRESS', weight: 4 },
    { status: 'NOT_STARTED', weight: 2 },
  ]);
  // 2*1 + 2*0.5 + 4*0.25 + 2*0 = 4 of 10
  assert.equal(posture.creditedWeight, 4);
  assert.equal(posture.applicableWeight, 10);
  assert.equal(posture.score, 40);
  assert.equal(posture.band, 'AT_RISK');
});

test('not-applicable controls leave the denominator instead of counting as a pass', () => {
  const posture = computePosture([
    { status: 'NOT_STARTED', weight: 1 },
    { status: 'NOT_APPLICABLE', weight: 9 },
  ]);
  assert.equal(posture.applicableWeight, 1);
  assert.equal(posture.score, 0);
  assert.equal(posture.counts.NOT_APPLICABLE, 1);
  assert.equal(posture.total, 2);
});

test('weighting lets a heavy control dominate the score', () => {
  const posture = computePosture([
    { status: 'IMPLEMENTED', weight: 3 },
    { status: 'NOT_STARTED', weight: 9 },
  ]);
  assert.equal(posture.score, 25);
});

test('scores are rounded to one decimal place without floating point drift', () => {
  const posture = computePosture([
    { status: 'IMPLEMENTED', weight: 1 },
    { status: 'NOT_STARTED', weight: 1 },
    { status: 'NOT_STARTED', weight: 1 },
  ]);
  assert.equal(posture.score, 33.3);
  assert.equal(Number.isInteger(posture.score * 10), true);
});

test('a framework with no applicable controls is NOT_ASSESSED rather than perfect', () => {
  const posture = computePosture([{ status: 'NOT_APPLICABLE', weight: 2 }]);
  assert.equal(posture.score, 0);
  assert.equal(posture.band, 'NOT_ASSESSED');
  assert.equal(postureBand(100, 0), 'NOT_ASSESSED');
});

test('degenerate weights fall back to one', () => {
  const posture = computePosture([
    { status: 'IMPLEMENTED', weight: 0 },
    { status: 'NOT_STARTED', weight: Number.NaN },
  ]);
  assert.equal(posture.applicableWeight, 2);
  assert.equal(posture.score, 50);
});

test('bands follow the documented thresholds', () => {
  assert.equal(postureBand(90, 10), 'READY');
  assert.equal(postureBand(89.9, 10), 'PROGRESSING');
  assert.equal(postureBand(60, 10), 'PROGRESSING');
  assert.equal(postureBand(59.9, 10), 'AT_RISK');
  assert.equal(postureBand(0, 10), 'AT_RISK');
});

test('an empty framework reports zeroed counts', () => {
  const posture = computePosture([]);
  assert.equal(posture.score, 0);
  assert.equal(posture.total, 0);
  assert.equal(posture.band, 'NOT_ASSESSED');
  assert.deepEqual(posture.counts, emptyCounts());
});

test('only IMPLEMENTED requires evidence before it can be attested', () => {
  assert.equal(requiresEvidence('IMPLEMENTED'), true);
  for (const status of ['NOT_STARTED', 'IN_PROGRESS', 'PARTIAL', 'NOT_APPLICABLE'] as const) {
    assert.equal(requiresEvidence(status), false, status);
  }

  assert.match(
    attestationIssue({ status: 'IMPLEMENTED', evidenceCount: 0 }) ?? '',
    /at least one piece of evidence/,
  );
  assert.equal(attestationIssue({ status: 'IMPLEMENTED', evidenceCount: 1 }), null);
  assert.equal(attestationIssue({ status: 'PARTIAL', evidenceCount: 0 }), null);
});

test('partial and implemented are attestations; the rest are plans', () => {
  assert.equal(isAttested('IMPLEMENTED'), true);
  assert.equal(isAttested('PARTIAL'), true);
  assert.equal(isAttested('IN_PROGRESS'), false);
  assert.equal(isAttested('NOT_STARTED'), false);
  assert.equal(isAttested('NOT_APPLICABLE'), false);
});
