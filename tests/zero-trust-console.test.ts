import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import { canonicalize } from '@/server/audit/canonical';
import { postureSignaturePayload } from '@/server/services/zero-trust-support';
import {
  activateDevice,
  getDeviceDetail,
  registerDevice,
  submitPosture,
} from '@/server/services/devices';
import { approveEnforcement, requestEnforcement } from '@/server/services/enforcement';
import {
  admitDevice,
  createConnector,
  createSegment,
  recordConnectorHeartbeat,
} from '@/server/services/network';
import { createPolicyRule } from '@/server/services/policy';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  resetDatabase,
} from './helpers/database.ts';

const CHECKS = [
  { id: 'disk_encryption', status: 'PASS' as const },
  { id: 'firewall', status: 'PASS' as const },
];

function deviceKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey };
}

function signPosture(
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'],
  deviceId: string,
  collectedAt: Date,
) {
  const payload = postureSignaturePayload(deviceId, collectedAt, CHECKS);
  return sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64');
}

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

test('a device only becomes trusted after activation and a signed posture report', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const keys = deviceKeyPair();
  const device = await registerDevice(tenant.ctx, {
    name: 'MacBook',
    hardwareId: 'HW-1',
    publicKey: keys.publicKey,
    attestationKind: 'NONE',
    attestationVerified: false,
    managed: true,
    os: 'macos',
    osVersion: '15.1',
  });

  assert.equal(device.status, 'PENDING');
  assert.equal(device.trustState, 'UNKNOWN');

  const activated = await activateDevice(tenant.ctx, device.id);
  assert.equal(activated.status, 'ACTIVE');

  const collectedAt = new Date(Date.now() - 60_000);
  const unsigned = await submitPosture(tenant.ctx, device.id, {
    collectedAt,
    checks: CHECKS,
  });
  assert.equal(unsigned.signatureVerified, false);
  assert.equal(unsigned.device.trustState, 'UNKNOWN', 'an unverified report must not raise trust');

  const signedAt = new Date();
  const signed = await submitPosture(tenant.ctx, device.id, {
    collectedAt: signedAt,
    checks: CHECKS,
    signature: signPosture(keys.privateKey, device.id, signedAt),
  });
  assert.equal(signed.signatureVerified, true);
  assert.equal(signed.device.trustState, 'PARTIAL');
  assert.equal(signed.device.trustScore > unsigned.device.trustScore, true);

  // A signature over a different device's id must not verify.
  const otherKeys = deviceKeyPair();
  const other = await registerDevice(tenant.ctx, {
    name: 'Other',
    hardwareId: 'HW-2',
    publicKey: otherKeys.publicKey,
    attestationKind: 'NONE',
    attestationVerified: false,
    managed: true,
  });
  const laterAt = new Date(Date.now() + 1_000);
  const transplanted = await submitPosture(tenant.ctx, other.id, {
    collectedAt: laterAt,
    checks: CHECKS,
    signature: signPosture(keys.privateKey, device.id, laterAt),
  });
  assert.equal(transplanted.signatureVerified, false);
  assert.equal(transplanted.device.trustState, 'UNKNOWN');

  const chain = await verifyAuditChain(tenant.organization.id);
  assert.equal(chain.valid, true);
});

test('a device in another organization is not reachable through a known id', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const other = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const keys = deviceKeyPair();
  const device = await registerDevice(other.ctx, {
    name: 'Foreign',
    hardwareId: 'HW-F',
    publicKey: keys.publicKey,
    attestationKind: 'NONE',
    attestationVerified: false,
    managed: true,
  });

  await expectAppError(getDeviceDetail(tenant.organization.id, device.id), { statusCode: 404 });
});

test('connector heartbeats are recorded without breaking the audit chain', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const created = await createConnector(tenant.ctx, {
    name: 'RADIUS',
    kind: 'RADIUS',
    failMode: 'CLOSED',
    capabilities: [],
  });

  assert.equal(typeof created.token, 'string');
  assert.equal(created.connector.status, 'OFFLINE');

  // The heartbeat is the only place a machine actor writes to the audit chain;
  // auditing it with a non-user actor id used to violate the actor foreign key
  // and turn a perfectly valid heartbeat into a 500.
  await recordConnectorHeartbeat(created.connector.id, 'ONLINE');

  const refreshed = await prismaConnectorStatus(created.connector.id);
  assert.equal(refreshed.status, 'ONLINE');

  const chain = await verifyAuditChain(tenant.organization.id);
  assert.equal(chain.valid, true, 'heartbeat audit event must not break the hash chain');
});

async function prismaConnectorStatus(connectorId: string) {
  const { prisma } = await import('@/lib/prisma');
  return prisma.networkConnector.findUniqueOrThrow({
    where: { id: connectorId },
    select: { status: true, lastHeartbeatAt: true },
  });
}

test('admission fails closed for an unreachable connector and admits once it is online', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const keys = deviceKeyPair();
  const device = await registerDevice(tenant.ctx, {
    name: 'Laptop',
    hardwareId: 'HW-3',
    publicKey: keys.publicKey,
    attestationKind: 'NONE',
    attestationVerified: false,
    managed: true,
  });
  await activateDevice(tenant.ctx, device.id);
  const collectedAt = new Date();
  await submitPosture(tenant.ctx, device.id, {
    collectedAt,
    checks: CHECKS,
    signature: signPosture(keys.privateKey, device.id, collectedAt),
  });

  await createPolicyRule(tenant.ctx, {
    name: 'Allow partial trust',
    priority: 10,
    effect: 'ALLOW',
    enabled: true,
    conditions: { deviceTrustAtLeast: 'PARTIAL' },
  });

  const created = await createConnector(tenant.ctx, {
    name: 'Gateway',
    kind: 'GATEWAY',
    failMode: 'CLOSED',
    capabilities: [],
  });
  await createSegment(tenant.ctx, {
    name: 'LAN',
    cidr: '10.10.0.0/16',
    zone: 'CORPORATE',
    sensitivity: 'INTERNAL',
    connectorId: created.connector.id,
  });

  const request = {
    deviceId: device.id,
    subject: { kind: 'DEVICE' as const, id: device.id },
    action: 'network.admit',
    requestedZone: 'CORPORATE' as const,
    sourceAddress: '10.10.4.31',
    connectorId: created.connector.id,
    mfaSatisfied: true,
    resource: { type: 'network_segment', sensitivity: 'INTERNAL' as const },
  };

  const offline = await admitDevice({ organizationId: tenant.organization.id, request });
  assert.equal(offline.decision.outcome.verdict, 'ALLOW');
  assert.equal(offline.admission.admitted, false);
  assert.equal(offline.admission.reason, 'connector_unreachable_fail_closed');

  await recordConnectorHeartbeat(created.connector.id, 'ONLINE');
  const online = await admitDevice({ organizationId: tenant.organization.id, request });
  assert.equal(online.admission.admitted, true);
  assert.equal(online.admission.reason, 'allowed');
  assert.equal(online.admission.assignedZone, 'CORPORATE');
});

test('a lower-priority allow cannot override a higher-priority deny', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const keys = deviceKeyPair();
  const device = await registerDevice(tenant.ctx, {
    name: 'Untrusted',
    hardwareId: 'HW-4',
    publicKey: keys.publicKey,
    attestationKind: 'NONE',
    attestationVerified: false,
    managed: true,
  });

  await createPolicyRule(tenant.ctx, {
    name: 'Deny unknown',
    priority: 1,
    effect: 'DENY',
    enabled: true,
    conditions: { deviceTrustAtLeast: 'UNKNOWN' },
  });
  await createPolicyRule(tenant.ctx, {
    name: 'Allow device action',
    priority: 100,
    effect: 'ALLOW',
    enabled: true,
    conditions: { actionIn: ['network.admit'] },
  });

  const result = await admitDevice({
    organizationId: tenant.organization.id,
    request: {
      deviceId: device.id,
      subject: { kind: 'DEVICE', id: device.id },
      action: 'network.admit',
      requestedZone: 'CORPORATE',
      mfaSatisfied: false,
      resource: { type: 'network_segment', sensitivity: 'INTERNAL' },
    },
  });

  assert.equal(result.decision.outcome.verdict, 'DENY');
  assert.equal(result.decision.outcome.matchedRuleName, 'Deny unknown');
});

test('an enforcement action cannot be approved by the operator who requested it', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const requested = await requestEnforcement(tenant.ctx, {
    kind: 'NETWORK_QUARANTINE',
    targetType: 'device',
    targetId: 'dev_target_1',
    targetLabel: 'Target device',
    payload: { blockSeconds: 900 },
    expiresInSeconds: 3600,
    idempotencyKey: 'idem-key-0001',
  });

  assert.equal(requested.action.state, 'REQUESTED');
  assert.equal(requested.action.secondApproverRequired, true);
  await expectAppError(approveEnforcement(tenant.ctx, requested.action.id, 'self'), {
    statusCode: 409,
  });
});
