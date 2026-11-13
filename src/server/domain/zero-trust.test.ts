import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { canonicalize } from '../audit/canonical';
import {
  assertAntiRollback,
  assertDistinctApprover,
  assertEnforcementTransition,
  assignCanary,
  checkCompatibility,
  cidrContains,
  compareVersions,
  computeRisk,
  computeTrustState,
  deriveDetections,
  evaluatePolicy,
  isTerminalEnforcementState,
  mapAdmission,
  parsePublisherKeys,
  releaseManifest,
  requiresSecondApprover,
  verifyManifestSignature,
  verifyRelease,
  ZeroTrustError,
  type PolicyDeviceFacts,
  type PolicyFactBundle,
  type PolicyRuleDefinition,
} from './zero-trust';

const AT = new Date('2026-03-02T10:00:00.000Z'); // Monday, business hours UTC.

const TRUSTED_DEVICE: PolicyDeviceFacts = {
  id: 'dev_1',
  managed: true,
  attestationVerified: true,
  trustState: 'TRUSTED',
  postureFresh: true,
  passedChecks: ['disk_encryption', 'edr_running'],
  failingChecks: [],
  unknownChecks: [],
};

function facts(overrides: Partial<PolicyFactBundle> = {}): PolicyFactBundle {
  return {
    subject: {
      kind: 'USER',
      id: 'usr_1',
      label: 'ada@example.test',
      role: 'ANALYST',
      attributes: { department: 'security', contractor: false },
    },
    device: TRUSTED_DEVICE,
    network: { zone: 'CORPORATE', connectorStatus: 'ONLINE', connectorFailMode: 'CLOSED' },
    resource: { type: 'asset', id: 'ast_1', sensitivity: 'INTERNAL' },
    action: 'asset.read',
    request: {
      at: AT,
      mfaSatisfied: true,
      approvalState: 'NONE',
      correlationId: 'corr_1',
      sourceIp: '10.0.0.5',
    },
    ...overrides,
  };
}

function rule(overrides: Partial<PolicyRuleDefinition>): PolicyRuleDefinition {
  return {
    id: 'rule_1',
    name: 'rule one',
    priority: 100,
    effect: 'ALLOW',
    enabled: true,
    conditions: {},
    ...overrides,
  };
}

test('risk accumulates named factors and saturates at 100', () => {
  const low = computeRisk(facts());
  assert.deepEqual(low.factors, []);
  assert.equal(low.score, 0);

  const high = computeRisk(
    facts({
      device: {
        id: 'dev_1',
        managed: false,
        attestationVerified: false,
        trustState: 'UNTRUSTED',
        postureFresh: false,
        passedChecks: [],
        failingChecks: ['disk_encryption'],
        unknownChecks: [],
      },
      network: { zone: 'QUARANTINE', connectorStatus: 'OFFLINE', connectorFailMode: 'CLOSED' },
      resource: { type: 'asset', id: 'ast_1', sensitivity: 'RESTRICTED' },
      request: {
        ...facts().request,
        at: new Date('2026-03-02T23:00:00.000Z'),
        mfaSatisfied: false,
      },
    }),
  );
  const codes = high.factors.map((factor) => factor.code);
  assert.deepEqual(codes, [
    'device_untrusted',
    'posture_stale',
    'device_unmanaged',
    'mfa_not_satisfied',
    'zone_quarantine',
    'sensitivity_restricted',
    'outside_business_hours',
  ]);
  assert.equal(high.score, 100);
});

test('a request that matches no rule is denied', () => {
  const outcome = evaluatePolicy({ facts: facts(), rules: [] });
  assert.equal(outcome.verdict, 'DENY');
  assert.equal(outcome.reason, 'default_deny');
  assert.equal(outcome.matchedRuleId, null);
  assert.deepEqual(outcome.obligations, ['block']);
  assert.equal(outcome.explanation.defaulted, true);
});

test('the first matching rule by priority decides, not the strongest effect', () => {
  const outcome = evaluatePolicy({
    facts: facts({ network: { ...facts().network, zone: 'GUEST' } }),
    rules: [
      rule({
        id: 'allow_guest',
        name: 'allow guests',
        priority: 10,
        effect: 'ALLOW',
        conditions: { zoneIn: ['GUEST'] },
      }),
      rule({
        id: 'deny_guest',
        name: 'deny guests',
        priority: 20,
        effect: 'DENY',
        conditions: { zoneIn: ['GUEST'] },
      }),
    ],
  });
  assert.equal(outcome.verdict, 'ALLOW');
  assert.equal(outcome.matchedRuleId, 'allow_guest');
  assert.ok(outcome.explanation.steps.length >= 1);
});

test('a condition that does not pass lets the next rule decide', () => {
  const outcome = evaluatePolicy({
    facts: facts(),
    rules: [
      rule({
        id: 'require_encryption',
        name: 'require encryption',
        priority: 10,
        effect: 'DENY',
        conditions: { postureCheckFailed: ['disk_encryption'] },
      }),
      rule({ id: 'allow_all', name: 'allow all', priority: 20, effect: 'ALLOW' }),
    ],
  });
  assert.equal(outcome.matchedRuleId, 'allow_all');
  const first = outcome.explanation.steps[0];
  assert.equal(first?.matched, false);
  assert.deepEqual(first?.failedConditions, ['postureCheckFailed']);
});

test('a satisfied step-up is skipped so the caller cannot loop on it', () => {
  const outcome = evaluatePolicy({
    facts: facts({ request: { ...facts().request, mfaSatisfied: true } }),
    rules: [
      rule({
        id: 'step_up',
        name: 'step up',
        priority: 10,
        effect: 'STEP_UP',
        conditions: { sensitivityAtLeast: 'INTERNAL' },
      }),
      rule({
        id: 'allow',
        name: 'allow analysts',
        priority: 20,
        effect: 'ALLOW',
        conditions: { roleIn: ['ANALYST'] },
      }),
    ],
  });
  assert.equal(outcome.verdict, 'ALLOW');
  assert.deepEqual(outcome.explanation.stepUpAlreadySatisfied, ['step up']);

  const unsatisfied = evaluatePolicy({
    facts: facts({ request: { ...facts().request, mfaSatisfied: false } }),
    rules: [
      rule({
        id: 'step_up',
        name: 'step up',
        priority: 10,
        effect: 'STEP_UP',
        conditions: { sensitivityAtLeast: 'INTERNAL' },
      }),
      rule({ id: 'allow', name: 'allow analysts', priority: 20, effect: 'ALLOW' }),
    ],
  });
  assert.equal(unsatisfied.verdict, 'STEP_UP');
  assert.deepEqual(unsatisfied.obligations, ['require_mfa']);
});

test('an enabled rule with unreadable conditions denies before a later allow', () => {
  const outcome = evaluatePolicy({
    facts: facts(),
    rules: [
      rule({
        id: 'broken',
        name: 'broken',
        priority: 10,
        effect: 'ALLOW',
        conditions: { zoneIn: ['MOON'] },
      }),
      rule({ id: 'allow', name: 'allow all', priority: 20, effect: 'ALLOW' }),
    ],
  });
  assert.equal(outcome.verdict, 'DENY');
  assert.equal(outcome.reason, 'invalid_rule');
  assert.equal(outcome.explanation.invalidRule?.ruleId, 'broken');
  assert.ok(outcome.obligations.includes('fix_policy_rule'));
});

test('unknown condition keys are rejected instead of ignored', () => {
  const outcome = evaluatePolicy({
    facts: facts(),
    rules: [
      rule({ id: 'typo', name: 'typo rule', priority: 10, conditions: { zone: 'CORPORATE' } }),
    ],
  });
  assert.equal(outcome.reason, 'invalid_rule');
  assert.match(outcome.explanation.invalidRule?.reason ?? '', /unknown condition/);
});

test('disabled rules are not evaluated', () => {
  const outcome = evaluatePolicy({
    facts: facts(),
    rules: [
      rule({
        id: 'off',
        name: 'off',
        priority: 1,
        enabled: false,
        conditions: { zoneIn: ['CORPORATE'] },
      }),
    ],
  });
  assert.equal(outcome.reason, 'default_deny');
  assert.equal(outcome.explanation.steps.length, 0);
});

test('attribute and risk conditions read the stored facts', () => {
  const outcome = evaluatePolicy({
    facts: facts({ resource: { type: 'asset', id: 'ast_1', sensitivity: 'RESTRICTED' } }),
    rules: [
      rule({
        id: 'contractor_deny',
        name: 'contractors denied',
        priority: 10,
        effect: 'DENY',
        conditions: { attributeEquals: { contractor: false }, sensitivityAtLeast: 'CONFIDENTIAL' },
      }),
    ],
  });
  assert.equal(outcome.verdict, 'DENY');
  assert.equal(outcome.riskScore, 20);

  const highRisk = evaluatePolicy({
    facts: facts({
      device: { ...TRUSTED_DEVICE, trustState: 'UNTRUSTED', postureFresh: false },
      request: { ...facts().request, mfaSatisfied: false },
    }),
    rules: [
      rule({
        id: 'risky',
        name: 'risky',
        priority: 10,
        effect: 'STEP_UP',
        conditions: { riskAtLeast: 40 },
      }),
    ],
  });
  assert.equal(highRisk.verdict, 'STEP_UP');
  assert.equal(highRisk.riskScore, 60);
});

test('trust requires verified, fresh, passing posture from a managed attested device', () => {
  const trusted = computeTrustState({
    status: 'ACTIVE',
    managed: true,
    attestationVerified: true,
    now: AT,
    posture: {
      collectedAt: new Date('2026-03-02T09:30:00.000Z'),
      expiresAt: new Date('2026-03-02T10:30:00.000Z'),
      signatureVerified: true,
      checks: [
        { id: 'disk_encryption', status: 'PASS' },
        { id: 'edr_running', status: 'PASS' },
      ],
    },
  });
  assert.equal(trusted.state, 'TRUSTED');
  assert.equal(trusted.score, 100);

  const failed = computeTrustState({
    status: 'ACTIVE',
    managed: true,
    attestationVerified: true,
    now: AT,
    posture: {
      collectedAt: new Date('2026-03-02T09:30:00.000Z'),
      expiresAt: new Date('2026-03-02T10:30:00.000Z'),
      signatureVerified: true,
      checks: [{ id: 'edr_running', status: 'FAIL' }],
    },
  });
  assert.equal(failed.state, 'UNTRUSTED');
  assert.deepEqual(failed.reasons, ['posture_failed']);
  assert.ok(failed.score <= 39);
});

test('unverified, stale, incomplete and unmanaged posture each degrade by name', () => {
  const base = {
    status: 'ACTIVE' as const,
    managed: true,
    attestationVerified: true,
    now: AT,
  };
  const unverified = computeTrustState({
    ...base,
    posture: {
      collectedAt: AT,
      expiresAt: new Date('2026-03-02T11:00:00.000Z'),
      signatureVerified: false,
      checks: [{ id: 'edr_running', status: 'PASS' }],
    },
  });
  assert.equal(unverified.state, 'UNKNOWN');
  assert.deepEqual(unverified.reasons, ['posture_unverified']);

  const stale = computeTrustState({
    ...base,
    posture: {
      collectedAt: new Date('2026-03-02T06:00:00.000Z'),
      expiresAt: new Date('2026-03-02T07:00:00.000Z'),
      signatureVerified: true,
      checks: [{ id: 'edr_running', status: 'PASS' }],
    },
  });
  assert.equal(stale.state, 'UNKNOWN');
  assert.deepEqual(stale.reasons, ['posture_stale']);

  const incomplete = computeTrustState({
    ...base,
    posture: {
      collectedAt: AT,
      expiresAt: new Date('2026-03-02T11:00:00.000Z'),
      signatureVerified: true,
      checks: [{ id: 'edr_running', status: 'UNKNOWN' }],
    },
  });
  assert.equal(incomplete.state, 'PARTIAL');
  assert.deepEqual(incomplete.reasons, ['posture_incomplete']);

  const unmanaged = computeTrustState({
    ...base,
    managed: false,
    posture: {
      collectedAt: AT,
      expiresAt: new Date('2026-03-02T11:00:00.000Z'),
      signatureVerified: true,
      checks: [{ id: 'edr_running', status: 'PASS' }],
    },
  });
  assert.equal(unmanaged.state, 'PARTIAL');
  assert.deepEqual(unmanaged.reasons, ['device_unmanaged']);
});

test('a suspended device is untrusted regardless of its posture', () => {
  const assessment = computeTrustState({
    status: 'SUSPENDED',
    managed: true,
    attestationVerified: true,
    now: AT,
    posture: {
      collectedAt: AT,
      expiresAt: new Date('2026-03-02T11:00:00.000Z'),
      signatureVerified: true,
      checks: [{ id: 'edr_running', status: 'PASS' }],
    },
  });
  assert.equal(assessment.state, 'UNTRUSTED');
  assert.equal(assessment.score, 0);
});

test('an unreachable connector quarantines when closed and degrades when open', () => {
  const closed = mapAdmission({
    verdict: 'ALLOW',
    requestedZone: 'CORPORATE',
    connector: { status: 'OFFLINE', failMode: 'CLOSED' },
  });
  assert.equal(closed.admitted, false);
  assert.equal(closed.assignedZone, 'QUARANTINE');
  assert.equal(closed.reason, 'connector_unreachable_fail_closed');

  const open = mapAdmission({
    verdict: 'ALLOW',
    requestedZone: 'CORPORATE',
    connector: { status: 'OFFLINE', failMode: 'OPEN' },
  });
  assert.equal(open.admitted, true);
  assert.equal(open.reason, 'connector_unreachable_fail_open');
  assert.ok(open.restrictions.includes('degraded_admission'));

  const missing = mapAdmission({ verdict: 'ALLOW', requestedZone: 'GUEST', connector: null });
  assert.equal(missing.reason, 'connector_unreachable_fail_closed');
});

test('admission maps every verdict to a network outcome', () => {
  const connector = { status: 'ONLINE' as const, failMode: 'CLOSED' as const };
  assert.equal(
    mapAdmission({ verdict: 'ALLOW', requestedZone: 'CORPORATE', connector }).admitted,
    true,
  );
  assert.equal(
    mapAdmission({ verdict: 'DENY', requestedZone: 'CORPORATE', connector }).assignedZone,
    null,
  );
  const quarantine = mapAdmission({ verdict: 'QUARANTINE', requestedZone: 'CORPORATE', connector });
  assert.equal(quarantine.assignedZone, 'QUARANTINE');
  assert.equal(quarantine.quarantine, true);
  assert.equal(
    mapAdmission({ verdict: 'STEP_UP', requestedZone: 'CORPORATE', connector }).admitted,
    false,
  );
});

test('CIDR matching uses the longest prefix', () => {
  assert.equal(cidrContains('10.0.0.0/8', '10.1.2.3'), true);
  assert.equal(cidrContains('10.1.0.0/16', '10.2.0.1'), false);
  assert.equal(cidrContains('192.168.1.10/32', '192.168.1.10'), true);
  assert.equal(cidrContains('192.168.1.10/32', '192.168.1.11'), false);
  assert.equal(cidrContains('10.0.0.0/8', '::1'), false);
  assert.equal(cidrContains('10.0.0.0/33', '10.0.0.1'), false);
});

test('detections carry supporting flows and telemetry freshness', () => {
  const now = new Date('2026-03-02T10:05:00.000Z');
  const segments = [
    {
      id: 'seg_corp',
      cidr: '10.0.0.0/16',
      zone: 'CORPORATE' as const,
      sensitivity: 'INTERNAL' as const,
    },
    { id: 'seg_ot', cidr: '10.9.0.0/16', zone: 'OT' as const, sensitivity: 'RESTRICTED' as const },
    {
      id: 'seg_quar',
      cidr: '10.66.0.0/16',
      zone: 'QUARANTINE' as const,
      sensitivity: 'INTERNAL' as const,
    },
  ];
  const flows = [
    ...Array.from({ length: 14 }, (_, index) => ({
      id: `flow_scan_${index}`,
      sourceAddress: '10.0.0.5',
      sourcePort: 50000 + index,
      destinationAddress: '10.0.0.9',
      destinationPort: 1 + index,
      protocol: 'tcp',
      bytes: 64,
      observedAt: new Date('2026-03-02T10:00:00.000Z'),
      segmentId: 'seg_corp',
    })),
    {
      id: 'flow_quarantine',
      sourceAddress: '10.66.0.7',
      sourcePort: 40000,
      destinationAddress: '10.9.1.1',
      destinationPort: 22,
      protocol: 'tcp',
      bytes: 1024,
      observedAt: new Date('2026-03-02T10:01:00.000Z'),
      segmentId: 'seg_quar',
    },
  ];

  const detections = deriveDetections({ flows, segments, now });
  const byRule = new Map(detections.map((detection) => [detection.ruleKey, detection]));

  const scan = byRule.get('port_scan');
  assert.ok(scan);
  assert.equal(scan.severity, 'HIGH');
  assert.equal(scan.observations.flowIds.length, 14);
  assert.equal(scan.observations.facts.distinctPorts, 14);
  assert.equal(scan.firstSeenAt.toISOString(), '2026-03-02T10:00:00.000Z');
  assert.equal(scan.freshUntil.toISOString(), '2026-03-02T11:00:00.000Z');

  const quarantine = byRule.get('quarantine_egress');
  assert.ok(quarantine);
  assert.equal(quarantine.severity, 'CRITICAL');
  assert.equal(quarantine.subjectKey, '10.66.0.7');

  // The OT destination is reached from QUARANTINE, not EXTERNAL, so no inbound
  // OT detection is produced for this flow.
  assert.equal(byRule.has('ot_external_inbound'), false);
});

test('bulk transfer severity scales with volume', () => {
  const segments = [
    {
      id: 'seg_corp',
      cidr: '10.0.0.0/16',
      zone: 'CORPORATE' as const,
      sensitivity: 'INTERNAL' as const,
    },
    {
      id: 'seg_ext',
      cidr: '203.0.113.0/24',
      zone: 'EXTERNAL' as const,
      sensitivity: 'PUBLIC' as const,
    },
  ];
  const flows = [
    {
      id: 'flow_big',
      sourceAddress: '10.0.0.5',
      sourcePort: 51000,
      destinationAddress: '203.0.113.7',
      destinationPort: 443,
      protocol: 'tcp',
      bytes: 300 * 1024 * 1024,
      observedAt: AT,
      segmentId: 'seg_corp',
    },
  ];
  const detections = deriveDetections({ flows, segments, now: AT });
  const bulk = detections.find((detection) => detection.ruleKey === 'bulk_transfer');
  assert.equal(bulk?.severity, 'HIGH');
  const egress = detections.find((detection) => detection.ruleKey === 'external_egress');
  assert.equal(egress?.severity, 'MEDIUM');
});

test('versions compare by semver precedence and reject nonsense', () => {
  assert.equal(compareVersions('1.2.3', '1.2.4'), -1);
  assert.equal(compareVersions('1.10.0', '1.9.9'), 1);
  assert.equal(compareVersions('2.0.0', '2.0.0'), 0);
  assert.equal(compareVersions('1.0.0-rc.1', '1.0.0'), -1);
  assert.equal(compareVersions('1.0.0-rc.2', '1.0.0-rc.10'), -1);
  assert.equal(compareVersions('14.5', '14.4.1'), 1);
  assert.throws(() => compareVersions('latest', '1.0.0'), ZeroTrustError);
});

test('anti-rollback blocks a downgrade and honours the release floor', () => {
  assert.doesNotThrow(() =>
    assertAntiRollback({ currentVersion: '1.2.2', targetVersion: '1.2.3', minVersion: '1.2.0' }),
  );
  assert.throws(
    () => assertAntiRollback({ currentVersion: '1.2.3', targetVersion: '1.2.3', minVersion: null }),
    /not newer/,
  );
  assert.throws(
    () =>
      assertAntiRollback({ currentVersion: '1.2.0', targetVersion: '1.1.9', minVersion: '1.2.0' }),
    /below the release floor/,
  );
  assert.throws(
    () => assertAntiRollback({ currentVersion: null, targetVersion: '1.0', minVersion: null }),
    /not semver/,
  );
});

test('compatibility checks the OS and its version bounds', () => {
  const spec = { os: ['macOS', 'Windows'], minOsVersion: '13.0', maxOsVersion: '15.9' };
  assert.deepEqual(checkCompatibility(spec, { os: 'macos', osVersion: '14.5' }), {
    compatible: true,
    reasons: [],
  });
  assert.deepEqual(checkCompatibility(spec, { os: 'linux', osVersion: '6.1' }).reasons, [
    'os_not_supported',
    'os_too_old',
  ]);
  assert.deepEqual(checkCompatibility(spec, { os: 'macOS', osVersion: '12.6' }).reasons, [
    'os_too_old',
  ]);
  assert.deepEqual(checkCompatibility(spec, { os: 'macOS', osVersion: '16.0' }).reasons, [
    'os_too_new',
  ]);
  assert.deepEqual(checkCompatibility(spec, { os: 'macOS', osVersion: null }).reasons, [
    'os_version_unknown',
  ]);
});

test('canary selection is deterministic and monotonic in percentage', () => {
  const devices = Array.from({ length: 200 }, (_, index) => `dev_${index}`);
  const ten = assignCanary(devices, 10);
  const twenty = assignCanary(devices, 20);
  assert.deepEqual(assignCanary(devices, 10), ten);
  assert.ok(ten.length > 0 && ten.length < twenty.length);
  for (const deviceId of ten) assert.ok(twenty.includes(deviceId));
  assert.deepEqual(assignCanary(devices, 0), []);
  assert.equal(assignCanary(devices, 100).length, devices.length);
});

test('manifest signatures verify with Ed25519 and fail after tampering', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const material = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const manifest = releaseManifest({
    product: 'cybernorf-agent',
    version: '1.4.0',
    channel: 'stable',
    artifactUrl: 'https://updates.example.test/agent-1.4.0.pkg',
    sha256: 'a'.repeat(64),
    minVersion: '1.2.0',
    compatibility: { os: ['macOS'] },
  });
  const signature = sign(null, Buffer.from(canonicalize(manifest), 'utf8'), privateKey).toString(
    'base64',
  );

  assert.deepEqual(
    verifyManifestSignature({ manifest, signatureBase64: signature, publicKey: material }),
    {
      valid: true,
    },
  );

  const tampered = { ...manifest, artifactUrl: 'https://evil.example.test/agent.pkg' };
  const invalid = verifyManifestSignature({
    manifest: tampered,
    signatureBase64: signature,
    publicKey: material,
  });
  assert.equal(invalid.valid, false);
  assert.equal(invalid.reason, 'signature_invalid');

  const keys = parsePublisherKeys(`release-2026:${material}, other:${material}`);
  assert.equal(keys.size, 2);
  assert.equal(
    verifyRelease({
      manifest,
      signatureBase64: signature,
      publisherKey: keys.get('release-2026') ?? null,
      artifactSha256: 'a'.repeat(64),
    }).valid,
    true,
  );
  assert.equal(
    verifyRelease({
      manifest,
      signatureBase64: signature,
      publisherKey: keys.get('release-2026') ?? null,
      artifactSha256: 'b'.repeat(64),
    }).reason,
    'digest_mismatch',
  );
  assert.equal(
    verifyRelease({
      manifest,
      signatureBase64: signature,
      publisherKey: null,
      artifactSha256: 'a'.repeat(64),
    }).reason,
    'publisher_key_unknown',
  );
});

test('enforcement transitions are one-way and terminal states stay terminal', () => {
  assert.doesNotThrow(() => assertEnforcementTransition('REQUESTED', 'APPROVED'));
  assert.doesNotThrow(() => assertEnforcementTransition('DISPATCHED', 'ACKNOWLEDGED'));
  assert.throws(() => assertEnforcementTransition('REQUESTED', 'VERIFIED'), ZeroTrustError);
  assert.throws(() => assertEnforcementTransition('VERIFIED', 'FAILED'), ZeroTrustError);
  assert.equal(isTerminalEnforcementState('VERIFIED'), true);
  assert.equal(isTerminalEnforcementState('ACKNOWLEDGED'), false);
});

test('only network-severing actions need a second approver', () => {
  assert.equal(requiresSecondApprover('SESSION_REVOKE'), false);
  assert.equal(requiresSecondApprover('ENDPOINT_ISOLATE'), true);
  assert.equal(requiresSecondApprover('CERT_REVOKE'), true);
  assert.doesNotThrow(() => assertDistinctApprover('usr_1', 'usr_2'));
  assert.throws(
    () => assertDistinctApprover('usr_1', 'usr_1'),
    /cannot be approved by its requester/,
  );
});
