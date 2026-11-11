import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { AssetCriticality, FindingSeverity } from '@/generated/prisma/client';
import {
  REMEDIATION_SLA_DAYS,
  computeRiskScore,
  remediationDueAt,
  remediationState,
  summarizeRemediation,
  summarizeResolutions,
} from './risk';

const DAY = 86_400_000;
const NOW = new Date('2026-11-11T12:00:00.000Z');
const SEVERITIES: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CRITICALITIES: AssetCriticality[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

test('risk score stays inside 0-100 for every input combination', () => {
  for (const severity of SEVERITIES) {
    for (const criticality of [...CRITICALITIES, null]) {
      for (const cvss of [null, 0, 5, 10, 12, -3, Number.NaN]) {
        const score = computeRiskScore({
          severity,
          cvssScore: cvss,
          assetCriticality: criticality,
        });
        assert.equal(
          Number.isInteger(score),
          true,
          `${severity}/${criticality}/${cvss} is not an integer`,
        );
        assert.ok(
          score >= 0 && score <= 100,
          `${severity}/${criticality}/${cvss} produced ${score}`,
        );
      }
    }
  }
});

test('higher severity always outranks lower severity at equal exposure', () => {
  const scores = SEVERITIES.map((severity) => computeRiskScore({ severity }));
  assert.deepEqual(scores, [90, 70, 45, 20, 5]);
  for (let index = 1; index < scores.length; index += 1) {
    assert.ok(scores[index - 1]! > scores[index]!, 'severity scale is not descending');
  }
});

test('a real CVSS vector pulls the score toward the CVSS scale', () => {
  // 90 * 0.6 + 100 * 0.4 = 94, then x1.25 for a critical asset and clamped at 100.
  assert.equal(
    computeRiskScore({ severity: 'CRITICAL', cvssScore: 10, assetCriticality: 'CRITICAL' }),
    100,
  );
  // 70 * 0.6 + 50 * 0.4 = 62, then x0.85 for a low-value asset.
  assert.equal(computeRiskScore({ severity: 'HIGH', cvssScore: 5, assetCriticality: 'LOW' }), 53);
  // A negative vector is treated as zero rather than lowering the score below
  // what the declared severity justifies.
  assert.equal(
    computeRiskScore({ severity: 'CRITICAL', cvssScore: -5, assetCriticality: 'CRITICAL' }),
    68,
  );
});

test('an INFO finding cannot be lifted into the critical band by asset criticality', () => {
  const score = computeRiskScore({
    severity: 'INFO',
    cvssScore: 10,
    assetCriticality: 'CRITICAL',
  });
  assert.ok(score < 90, `INFO finding scored ${score}, which is critical territory`);
});

test('a missing, null or non-finite CVSS score falls back to the severity base', () => {
  for (const severity of SEVERITIES) {
    const base = computeRiskScore({ severity });
    assert.equal(computeRiskScore({ severity, cvssScore: null }), base);
    assert.equal(computeRiskScore({ severity, cvssScore: Number.NaN }), base);
  }
});

test('remediation deadlines follow the severity window from first observation', () => {
  const firstSeenAt = new Date('2026-01-01T00:00:00.000Z');
  for (const severity of SEVERITIES) {
    const dueAt = remediationDueAt({ severity, firstSeenAt });
    assert.equal(dueAt.getTime() - firstSeenAt.getTime(), REMEDIATION_SLA_DAYS[severity] * DAY);
  }
});

test('remediation state separates overdue, due soon, on track and unscheduled', () => {
  assert.equal(
    remediationState({ dueAt: new Date(NOW.getTime() - DAY), status: 'OPEN', now: NOW }),
    'OVERDUE',
  );
  assert.equal(
    remediationState({ dueAt: new Date(NOW.getTime() + 3 * DAY), status: 'TRIAGED', now: NOW }),
    'DUE_SOON',
  );
  assert.equal(
    remediationState({
      dueAt: new Date(NOW.getTime() + 30 * DAY),
      status: 'IN_PROGRESS',
      now: NOW,
    }),
    'ON_TRACK',
  );
  assert.equal(remediationState({ dueAt: null, status: 'OPEN', now: NOW }), 'UNSCHEDULED');
});

test('a closed finding is never reported as overdue', () => {
  const dueAt = new Date(NOW.getTime() - 30 * DAY);
  for (const status of ['RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'] as const) {
    assert.equal(remediationState({ dueAt, status, now: NOW }), 'CLOSED');
  }
});

test('resolution metrics report SLA compliance and mean time to resolve', () => {
  const created = new Date('2026-01-01T00:00:00.000Z');
  const metrics = summarizeResolutions([
    {
      status: 'RESOLVED',
      createdAt: created,
      // Four days to fix, deadline was ten days out: within SLA.
      resolvedAt: new Date(created.getTime() + 4 * DAY),
      dueAt: new Date(created.getTime() + 10 * DAY),
    },
    {
      status: 'RESOLVED',
      createdAt: created,
      // Nineteen days to fix against the same deadline: missed.
      resolvedAt: new Date(created.getTime() + 19 * DAY),
      dueAt: new Date(created.getTime() + 10 * DAY),
    },
    // No resolution timestamp: ignored by both averages.
    { status: 'RESOLVED', createdAt: created, resolvedAt: null, dueAt: null },
    // Still open: not part of resolution metrics.
    { status: 'OPEN', createdAt: created, resolvedAt: null, dueAt: null },
  ]);

  assert.equal(metrics.slaCompliance, 50);
  assert.equal(metrics.meanTimeToResolveDays, 11.5);
  assert.equal(metrics.sampleSize, 2);
});

test('resolution metrics are null instead of zero when there is no data', () => {
  assert.deepEqual(summarizeResolutions([]), {
    slaCompliance: null,
    meanTimeToResolveDays: null,
    sampleSize: 0,
  });
});

test('remediation summary counts open work and ignores closed findings', () => {
  const created = new Date(NOW.getTime() - 100 * DAY);
  const metrics = summarizeRemediation(
    [
      {
        status: 'OPEN',
        createdAt: created,
        resolvedAt: null,
        dueAt: new Date(NOW.getTime() - DAY),
      },
      {
        status: 'TRIAGED',
        createdAt: created,
        resolvedAt: null,
        dueAt: new Date(NOW.getTime() + 2 * DAY),
      },
      { status: 'IN_PROGRESS', createdAt: created, resolvedAt: null, dueAt: null },
      {
        status: 'ACCEPTED_RISK',
        createdAt: created,
        resolvedAt: null,
        dueAt: new Date(NOW.getTime() - 30 * DAY),
      },
      {
        status: 'RESOLVED',
        createdAt: created,
        // Resolved ten days after its deadline: a miss.
        resolvedAt: new Date(NOW.getTime() - 30 * DAY),
        dueAt: new Date(NOW.getTime() - 40 * DAY),
      },
    ],
    NOW,
  );

  assert.equal(metrics.open, 3);
  assert.equal(metrics.overdue, 1);
  assert.equal(metrics.dueSoon, 1);
  // The only resolution missed its deadline: 100 days to create, 30 to resolve.
  assert.equal(metrics.slaCompliance, 0);
  assert.equal(metrics.meanTimeToResolveDays, 70);
});
