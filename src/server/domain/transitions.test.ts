import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  FINDING_STATUSES,
  INCIDENT_STATUSES,
  allowedFindingTransitions,
  allowedIncidentTransitions,
  canTransitionFinding,
  canTransitionIncident,
  isTerminalFindingStatus,
} from './transitions.ts';

test('findings follow the documented lifecycle', () => {
  assert.deepEqual(allowedFindingTransitions('OPEN'), [
    'TRIAGED',
    'IN_PROGRESS',
    'RESOLVED',
    'ACCEPTED_RISK',
    'FALSE_POSITIVE',
  ]);
  assert.equal(canTransitionFinding('OPEN', 'TRIAGED'), true);
  assert.equal(canTransitionFinding('IN_PROGRESS', 'RESOLVED'), true);
  assert.equal(canTransitionFinding('RESOLVED', 'IN_PROGRESS'), false);
  assert.equal(canTransitionFinding('FALSE_POSITIVE', 'OPEN'), true);
  assert.equal(canTransitionFinding('TRIAGED', 'OPEN'), false);
});

test('incidents can only move forward through investigation states', () => {
  assert.equal(canTransitionIncident('OPEN', 'INVESTIGATING'), true);
  assert.equal(canTransitionIncident('OPEN', 'CONTAINED'), true);
  assert.equal(canTransitionIncident('CONTAINED', 'CLOSED'), false);
  assert.equal(canTransitionIncident('RESOLVED', 'CLOSED'), true);
  assert.equal(canTransitionIncident('CLOSED', 'OPEN'), true);
  assert.deepEqual(allowedIncidentTransitions('CLOSED'), ['OPEN']);
});

test('every status is reachable from at least one other status', () => {
  const reachable = new Set(
    FINDING_STATUSES.flatMap((status) => allowedFindingTransitions(status)),
  );
  for (const status of FINDING_STATUSES) {
    assert.equal(reachable.has(status), true, `${status} is unreachable`);
  }

  const reachableIncidents = new Set(
    INCIDENT_STATUSES.flatMap((status) => allowedIncidentTransitions(status)),
  );
  for (const status of INCIDENT_STATUSES) {
    assert.equal(reachableIncidents.has(status), true, `${status} is unreachable`);
  }
});

test('terminal finding statuses are the three closure outcomes', () => {
  assert.equal(isTerminalFindingStatus('RESOLVED'), true);
  assert.equal(isTerminalFindingStatus('ACCEPTED_RISK'), true);
  assert.equal(isTerminalFindingStatus('FALSE_POSITIVE'), true);
  assert.equal(isTerminalFindingStatus('OPEN'), false);
  assert.equal(isTerminalFindingStatus('IN_PROGRESS'), false);
});
