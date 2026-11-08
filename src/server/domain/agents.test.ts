import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  AGENT_SCOPES,
  agentHasScope,
  agentTokenTtlDays,
  canTransitionAgent,
  defaultAgentScopes,
  hashAgentToken,
  initialAgentStatus,
  isAgentScope,
  isAgentTokenShape,
  issueAgentToken,
  runStatusForCounts,
  summarizeChecks,
} from './agents.ts';

const DAY_MS = 24 * 60 * 60 * 1000;

test('an issued token is shown in full once, while storage keeps only the hash', () => {
  const issued = issueAgentToken('BUILTIN');

  assert.match(issued.token, /^cna_[A-Za-z0-9_-]+$/);
  assert.equal(issued.prefix.length, 'cna_'.length + 6);
  assert.ok(issued.token.startsWith(issued.prefix));
  assert.equal(issued.hash, hashAgentToken(issued.token));
  assert.notStrictEqual(issued.token, issued.hash);
  assert.match(issued.hash, /^[0-9a-f]{64}$/);
});

test('every issue is unique, so two agents never share a credential', () => {
  const first = issueAgentToken('CUSTOM');
  const second = issueAgentToken('CUSTOM');

  assert.notStrictEqual(first.token, second.token);
  assert.notStrictEqual(first.hash, second.hash);
});

test('builtin credentials live a year and third-party credentials 90 days', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');

  assert.equal(agentTokenTtlDays('BUILTIN'), 365);
  assert.equal(agentTokenTtlDays('OPENAI'), 90);
  assert.equal(agentTokenTtlDays('ANTHROPIC'), 90);
  assert.equal(agentTokenTtlDays('OTHER'), 90);
  assert.equal(issueAgentToken('BUILTIN', now).expiresAt.getTime() - now.getTime(), 365 * DAY_MS);
  assert.equal(issueAgentToken('ANTHROPIC', now).expiresAt.getTime() - now.getTime(), 90 * DAY_MS);
});

test('the shape check rejects anything this platform did not mint', () => {
  assert.equal(isAgentTokenShape(issueAgentToken('BUILTIN').token), true);
  assert.equal(isAgentTokenShape('cna_short'), false);
  assert.equal(isAgentTokenShape('Bearer cna_abcdefghijklmnopqrstuvwxyz0123456789abcdef'), false);
  assert.equal(isAgentTokenShape('cna_abcdefghijklmnopqrstuvwxyz0123456789abc.def'), false);
  assert.equal(isAgentTokenShape(''), false);
});

test('builtin agents start active and every external source waits for approval', () => {
  assert.equal(initialAgentStatus('BUILTIN'), 'ACTIVE');
  assert.equal(initialAgentStatus('OPENAI'), 'PENDING_APPROVAL');
  assert.equal(initialAgentStatus('ANTHROPIC'), 'PENDING_APPROVAL');
  assert.equal(initialAgentStatus('CUSTOM'), 'PENDING_APPROVAL');
  assert.equal(initialAgentStatus('OTHER'), 'PENDING_APPROVAL');
});

test('lifecycle transitions never leave the revoked state', () => {
  assert.equal(canTransitionAgent('PENDING_APPROVAL', 'ACTIVE'), true);
  assert.equal(canTransitionAgent('PENDING_APPROVAL', 'REVOKED'), true);
  assert.equal(canTransitionAgent('PENDING_APPROVAL', 'SUSPENDED'), false);
  assert.equal(canTransitionAgent('ACTIVE', 'SUSPENDED'), true);
  assert.equal(canTransitionAgent('ACTIVE', 'REVOKED'), true);
  assert.equal(canTransitionAgent('SUSPENDED', 'ACTIVE'), true);
  assert.equal(canTransitionAgent('SUSPENDED', 'REVOKED'), true);
  assert.equal(canTransitionAgent('REVOKED', 'ACTIVE'), false);
  assert.equal(canTransitionAgent('REVOKED', 'SUSPENDED'), false);
});

test('run status is derived from the checks, never accepted from the agent', () => {
  assert.equal(
    runStatusForCounts({ checkCount: 0, passCount: 0, failCount: 0, skipCount: 0 }),
    'FAILED',
  );
  assert.equal(
    runStatusForCounts({ checkCount: 4, passCount: 3, failCount: 1, skipCount: 0 }),
    'COMPLETED',
  );
  assert.equal(
    runStatusForCounts({ checkCount: 4, passCount: 3, failCount: 0, skipCount: 1 }),
    'PARTIAL',
  );

  assert.deepEqual(summarizeChecks(['PASS', 'FAIL', 'SKIP', 'PASS']), {
    checkCount: 4,
    passCount: 2,
    failCount: 1,
    skipCount: 1,
  });
  // Anything that is not an explicit pass or fail counts as skipped evidence.
  assert.deepEqual(summarizeChecks(['ERROR']), {
    checkCount: 1,
    passCount: 0,
    failCount: 0,
    skipCount: 1,
  });
});

test('default scopes let an agent verify itself and report, and nothing more', () => {
  assert.deepEqual(defaultAgentScopes(), ['monitor.report', 'monitor.read']);
  // Each call returns a fresh array so one registration cannot mutate another's row.
  assert.notStrictEqual(defaultAgentScopes(), defaultAgentScopes());
  assert.deepEqual([...AGENT_SCOPES], ['monitor.report', 'monitor.read']);
  assert.equal(isAgentScope('monitor.report'), true);
  assert.equal(isAgentScope('agent.admin'), false);
  assert.equal(agentHasScope(['monitor.report'], 'monitor.report'), true);
  assert.equal(agentHasScope(['monitor.report'], 'monitor.read'), false);
});
