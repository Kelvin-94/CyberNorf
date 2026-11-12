import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  DEFAULT_JOB_LIMITS,
  JOB_LIMIT_CEILINGS,
  ScopeFormatError,
  addressSetsDiffer,
  cidrContainsAddress,
  cidrContainsCidr,
  durationLimitExceeded,
  evaluateAuthorization,
  evaluateDispatch,
  evaluateEngagementWindow,
  evaluateRedirectChain,
  evaluateScope,
  normalizeCidr,
  normalizeDomainRule,
  normalizeIpAddress,
  normalizeJobLimits,
  normalizeScopeValue,
  riskForCapability,
  workerEgressAllows,
  type ScopeRule,
} from './execution.ts';

const NOW = new Date('2026-11-11T12:00:00.000Z');

function rule(
  kind: 'INCLUDE' | 'EXCLUDE',
  targetType: 'DOMAIN' | 'IP_ADDRESS' | 'CIDR' | 'URL',
  value: string,
): ScopeRule {
  return { kind, targetType, value };
}

function engagement(overrides: Partial<Parameters<typeof evaluateEngagementWindow>[0]> = {}) {
  return {
    status: 'ACTIVE' as const,
    startsAt: new Date('2026-11-01T00:00:00.000Z'),
    endsAt: new Date('2026-12-01T00:00:00.000Z'),
    ...overrides,
  };
}

function approvedAuthorization(overrides: Partial<{ status: 'APPROVED'; expiresAt: Date }> = {}) {
  return {
    status: 'APPROVED' as const,
    expiresAt: new Date('2026-11-20T00:00:00.000Z'),
    ...overrides,
  };
}

test('a domain rule covers the host and its subdomains', () => {
  const rules = [rule('INCLUDE', 'DOMAIN', 'Example.COM')];
  assert.equal(evaluateScope(rules, { targetType: 'DOMAIN', value: 'example.com' }).allowed, true);
  assert.equal(
    evaluateScope(rules, { targetType: 'DOMAIN', value: 'api.example.com' }).allowed,
    true,
  );
  assert.equal(evaluateScope(rules, { targetType: 'DOMAIN', value: 'example.net' }).allowed, false);
  assert.equal(
    evaluateScope(rules, { targetType: 'DOMAIN', value: 'notexample.com' }).allowed,
    false,
  );
});

test('a wildcard rule excludes the apex host', () => {
  const rules = [rule('INCLUDE', 'DOMAIN', '*.example.com')];
  assert.equal(
    evaluateScope(rules, { targetType: 'DOMAIN', value: 'a.example.com' }).allowed,
    true,
  );
  assert.equal(evaluateScope(rules, { targetType: 'DOMAIN', value: 'example.com' }).allowed, false);
  assert.equal(normalizeDomainRule('*.Example.COM.'), '*.example.com');
});

test('an exclusion wins even when a narrower inclusion matches', () => {
  const rules = [
    rule('INCLUDE', 'DOMAIN', 'example.com'),
    rule('INCLUDE', 'DOMAIN', 'admin.example.com'),
    rule('EXCLUDE', 'DOMAIN', 'admin.example.com'),
  ];
  const decision = evaluateScope(rules, { targetType: 'DOMAIN', value: 'admin.example.com' });
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'excluded');
  assert.match(decision.matchedRule ?? '', /EXCLUDE/);
});

test('an empty scope allows nothing', () => {
  const decision = evaluateScope([], { targetType: 'DOMAIN', value: 'example.com' });
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'out_of_scope');
});

test('exclusions are evaluated for URL candidates too', () => {
  const rules = [
    rule('INCLUDE', 'DOMAIN', 'example.com'),
    rule('EXCLUDE', 'DOMAIN', 'billing.example.com'),
  ];
  assert.equal(
    evaluateScope(rules, { targetType: 'URL', value: 'https://app.example.com/login' }).allowed,
    true,
  );
  assert.equal(
    evaluateScope(rules, { targetType: 'URL', value: 'https://billing.example.com/pay' }).allowed,
    false,
  );
});

test('IP and CIDR rules match single addresses, ranges and URL literals', () => {
  const rules = [
    rule('INCLUDE', 'CIDR', '203.0.113.0/24'),
    rule('INCLUDE', 'IP_ADDRESS', '2001:db8::1'),
  ];
  assert.equal(
    evaluateScope(rules, { targetType: 'IP_ADDRESS', value: '203.0.113.55' }).allowed,
    true,
  );
  assert.equal(
    evaluateScope(rules, { targetType: 'IP_ADDRESS', value: '198.51.100.55' }).allowed,
    false,
  );
  assert.equal(
    evaluateScope(rules, { targetType: 'URL', value: 'http://203.0.113.55:8080/' }).allowed,
    true,
  );
  assert.equal(
    evaluateScope(rules, {
      targetType: 'IP_ADDRESS',
      value: '2001:0db8:0000:0000:0000:0000:0000:0001',
    }).allowed,
    true,
  );
  assert.equal(cidrContainsAddress('203.0.113.0/24', '203.0.113.0'), true);
  assert.equal(cidrContainsAddress('203.0.113.0/24', '203.0.114.0'), false);
  assert.equal(cidrContainsCidr('203.0.113.0/24', '203.0.113.128/25'), true);
  assert.equal(cidrContainsCidr('203.0.113.0/25', '203.0.113.0/24'), false);
  assert.equal(normalizeCidr('203.0.113.17/24'), '203.0.113.0/24');
});

test('a URL rule pins scheme, port and path prefix', () => {
  const rules = [rule('INCLUDE', 'URL', 'https://app.example.com/api')];
  assert.equal(
    evaluateScope(rules, { targetType: 'URL', value: 'https://app.example.com/api/v1/users' })
      .allowed,
    true,
  );
  assert.equal(
    evaluateScope(rules, { targetType: 'URL', value: 'https://app.example.com/apiv2' }).allowed,
    false,
  );
  assert.equal(
    evaluateScope(rules, { targetType: 'URL', value: 'http://app.example.com/api' }).allowed,
    false,
  );
  assert.equal(
    evaluateScope(rules, { targetType: 'URL', value: 'https://app.example.com:8443/api' }).allowed,
    false,
  );
  assert.equal(
    evaluateScope(rules, { targetType: 'DOMAIN', value: 'app.example.com' }).allowed,
    false,
    'a URL rule does not silently become a host-wide grant',
  );
});

test('an invalid target is reported before any rule is consulted', () => {
  const decision = evaluateScope([rule('INCLUDE', 'DOMAIN', 'example.com')], {
    targetType: 'IP_ADDRESS',
    value: 'not-an-address',
  });
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'invalid_target');
});

test('normalization rejects credentials, odd schemes and malformed hosts', () => {
  assert.throws(
    () => normalizeScopeValue('URL', 'https://user:pass@example.com/'),
    ScopeFormatError,
  );
  assert.throws(() => normalizeScopeValue('URL', 'file:///etc/passwd'), ScopeFormatError);
  assert.throws(() => normalizeScopeValue('DOMAIN', 'example.com/path'), ScopeFormatError);
  assert.throws(() => normalizeScopeValue('CIDR', '203.0.113.0/33'), ScopeFormatError);
  assert.equal(normalizeIpAddress('2001:0DB8::1'), normalizeIpAddress('2001:db8:0:0:0:0:0:1'));
});

test('an expired authorization denies execution', () => {
  const expired = approvedAuthorization({ expiresAt: new Date('2026-11-11T11:59:59.000Z') });
  const decision = evaluateAuthorization(expired, NOW);
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'authorization_expired');
});

test('pending, rejected, revoked and missing authorizations each deny with their own reason', () => {
  assert.equal(evaluateAuthorization(null, NOW).reason, 'no_authorization');
  assert.equal(
    evaluateAuthorization({ status: 'PENDING', expiresAt: NOW }, NOW).reason,
    'authorization_pending',
  );
  assert.equal(
    evaluateAuthorization({ status: 'REJECTED', expiresAt: NOW }, NOW).reason,
    'authorization_rejected',
  );
  assert.equal(
    evaluateAuthorization({ status: 'REVOKED', expiresAt: NOW }, NOW).reason,
    'authorization_revoked',
  );
  assert.equal(evaluateAuthorization(approvedAuthorization(), NOW).allowed, true);
});

test('an engagement must be active and inside its window', () => {
  assert.equal(evaluateEngagementWindow(engagement(), NOW).allowed, true);
  assert.equal(
    evaluateEngagementWindow(engagement({ status: 'PAUSED' }), NOW).reason,
    'engagement_not_active',
  );
  assert.equal(
    evaluateEngagementWindow(engagement({ startsAt: new Date('2026-11-12T00:00:00.000Z') }), NOW)
      .reason,
    'engagement_not_started',
  );
  assert.equal(
    evaluateEngagementWindow(engagement({ endsAt: new Date('2026-11-11T12:00:00.000Z') }), NOW)
      .reason,
    'engagement_ended',
  );
});

test('dispatch reports the earliest failing control', () => {
  const rules = [rule('INCLUDE', 'DOMAIN', 'example.com')];
  const base = {
    now: NOW,
    engagement: engagement(),
    authorization: approvedAuthorization(),
    rules,
    candidate: { targetType: 'DOMAIN' as const, value: 'example.com' },
  };
  assert.equal(evaluateDispatch(base).allowed, true);

  const ended = evaluateDispatch({ ...base, engagement: engagement({ status: 'CLOSED' }) });
  assert.equal(ended.reason, 'engagement_not_active');

  const expired = evaluateDispatch({
    ...base,
    authorization: approvedAuthorization({ expiresAt: new Date('2026-11-11T11:00:00.000Z') }),
  });
  assert.equal(expired.reason, 'authorization_expired');

  const outside = evaluateDispatch({
    ...base,
    candidate: { targetType: 'DOMAIN', value: 'other.example' },
  });
  assert.equal(outside.reason, 'out_of_scope');
});

test('a redirect that leaves scope is denied at the hop that leaves it', () => {
  const rules = [rule('INCLUDE', 'DOMAIN', 'example.com')];
  const allowed = evaluateRedirectChain(rules, 'https://example.com/start', [
    '/next',
    'https://api.example.com/v1',
  ]);
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.url, 'https://api.example.com/v1');

  const denied = evaluateRedirectChain(rules, 'https://example.com/start', [
    '/next',
    'https://elsewhere.example/collect',
  ]);
  assert.equal(denied.allowed, false);
  assert.equal(denied.reason, 'out_of_scope');
  assert.equal(denied.deniedAtHop, 2);
  assert.equal(denied.url, 'https://elsewhere.example/collect');
});

test('a redirect to an excluded host is denied even inside an included domain', () => {
  const rules = [
    rule('INCLUDE', 'DOMAIN', 'example.com'),
    rule('EXCLUDE', 'DOMAIN', 'internal.example.com'),
  ];
  const denied = evaluateRedirectChain(rules, 'https://example.com/', [
    'https://internal.example.com/admin',
  ]);
  assert.equal(denied.allowed, false);
  assert.equal(denied.reason, 'excluded');
});

test('a redirect with an unparseable location is denied, not skipped', () => {
  const rules = [rule('INCLUDE', 'DOMAIN', 'example.com')];
  const denied = evaluateRedirectChain(rules, 'https://example.com/', ['http://[invalid']);
  assert.equal(denied.allowed, false);
  assert.equal(denied.reason, 'invalid_target');
});

test('a DNS answer that changes between dispatch and start is detected', () => {
  assert.equal(
    addressSetsDiffer(['203.0.113.10', '203.0.113.11'], ['203.0.113.11', '203.0.113.10']),
    false,
    'order does not matter',
  );
  assert.equal(addressSetsDiffer(['203.0.113.10'], ['203.0.113.10', '198.51.100.7']), true);
  assert.equal(addressSetsDiffer(['2001:db8::1'], ['2001:0db8:0:0:0:0:0:1']), false);
  assert.equal(addressSetsDiffer([], ['203.0.113.10']), true);
  assert.equal(addressSetsDiffer(['203.0.113.10'], []), true);
});

test('a worker needs isolation and either name-based or address-pinned egress', () => {
  assert.equal(workerEgressAllows([], { host: 'example.com', addresses: ['203.0.113.10'] }), false);

  assert.equal(
    workerEgressAllows(['example.com'], { host: 'api.example.com', addresses: ['203.0.113.10'] }),
    true,
  );

  assert.equal(
    workerEgressAllows(['198.51.100.0/24'], { host: 'example.com', addresses: ['203.0.113.10'] }),
    false,
  );

  assert.equal(
    workerEgressAllows(['203.0.113.0/24'], {
      host: 'example.com',
      addresses: ['203.0.113.10', '203.0.113.11'],
    }),
    true,
  );

  assert.equal(
    workerEgressAllows(['203.0.113.0/24'], {
      host: 'example.com',
      addresses: ['203.0.113.10', '198.51.100.7'],
    }),
    false,
    'one address outside the pinned range is enough to deny',
  );

  assert.equal(
    workerEgressAllows(['203.0.113.10'], { host: '203.0.113.10', addresses: ['203.0.113.10'] }),
    true,
  );
});

test('risk is derived from the capability, never from the request', () => {
  assert.equal(riskForCapability('DNS_LOOKUP'), 'LOW');
  assert.equal(riskForCapability('HTTP_PROBE'), 'MEDIUM');
  assert.equal(riskForCapability('TLS_INSPECTION'), 'MEDIUM');
  assert.equal(riskForCapability('PORT_SCAN'), 'HIGH');
});

test('job limits default by risk and cannot exceed the platform ceiling', () => {
  assert.deepEqual(normalizeJobLimits('HIGH', null), DEFAULT_JOB_LIMITS.HIGH);
  assert.deepEqual(normalizeJobLimits('LOW', { maxRequests: 5 }), {
    ...DEFAULT_JOB_LIMITS.LOW,
    maxRequests: 5,
  });
  assert.throws(
    () =>
      normalizeJobLimits('LOW', { maxDurationSeconds: JOB_LIMIT_CEILINGS.maxDurationSeconds + 1 }),
    ScopeFormatError,
  );
  assert.throws(() => normalizeJobLimits('LOW', { maxRequests: 0 }), ScopeFormatError);
  assert.throws(() => normalizeJobLimits('LOW', { maxBytes: 1.5 }), ScopeFormatError);
});

test('a job that outlived its duration limit is flagged at completion', () => {
  const startedAt = new Date('2026-11-11T12:00:00.000Z');
  assert.equal(
    durationLimitExceeded(startedAt, new Date('2026-11-11T12:00:30.000Z'), DEFAULT_JOB_LIMITS.LOW),
    false,
  );
  assert.equal(
    durationLimitExceeded(startedAt, new Date('2026-11-11T12:00:31.000Z'), DEFAULT_JOB_LIMITS.LOW),
    true,
  );
});
