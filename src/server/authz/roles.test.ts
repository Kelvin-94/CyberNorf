import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  CAPABILITIES,
  MUTATING_CAPABILITIES,
  ORG_ROLES,
  can,
  isAtLeast,
  isMutating,
  isOrgRole,
  requiresSecondFactor,
  type Capability,
  type OrgRole,
} from './roles.ts';

test('viewers can only read', () => {
  for (const capability of CAPABILITIES) {
    const expected = capability.endsWith('.read');
    assert.equal(can('VIEWER', capability), expected, `VIEWER / ${capability}`);
  }
});

test('analysts manage investigation data but cannot delete or administer', () => {
  const granted: Capability[] = [
    'organization.read',
    'asset.read',
    'asset.create',
    'asset.update',
    'finding.read',
    'finding.create',
    'finding.update',
    'finding.import',
    'incident.read',
    'incident.create',
    'incident.update',
    'incident.note',
    'audit.read',
    'compliance.read',
    'compliance.evidence',
    // Agents are visible to every role, but connecting or approving one is an
    // administrative decision.
    'agent.read',
  ];
  for (const capability of granted) {
    assert.equal(can('ANALYST', capability), true, `ANALYST should have ${capability}`);
  }

  const denied: Capability[] = [
    'organization.update',
    'organization.manage_members',
    'asset.delete',
    'finding.delete',
    'incident.delete',
    // Attesting a control or adopting a framework is an ADMIN decision, even
    // though analysts can attach the evidence that supports it.
    'compliance.manage',
    'agent.manage',
  ];
  for (const capability of denied) {
    assert.equal(can('ANALYST', capability), false, `ANALYST should not have ${capability}`);
  }
});

test('compliance attestation requires a second factor for privileged roles', () => {
  assert.equal(requiresSecondFactor('OWNER', 'compliance.manage'), true);
  assert.equal(requiresSecondFactor('ADMIN', 'compliance.evidence'), true);
  assert.equal(requiresSecondFactor('OWNER', 'compliance.read'), false);
  assert.equal(requiresSecondFactor('ANALYST', 'compliance.manage'), false);
  assert.equal(requiresSecondFactor('OWNER', 'agent.manage'), true);
  assert.equal(requiresSecondFactor('ADMIN', 'agent.manage'), true);
  assert.equal(requiresSecondFactor('OWNER', 'agent.read'), false);
  assert.equal(requiresSecondFactor('ANALYST', 'agent.read'), false);
});

test('administrators can administer but never exceed owners', () => {
  // Only these capabilities are owner-exclusive, and each must stay listed so
  // a new one cannot appear without this test changing on purpose. Approving an
  // engagement authorization is reserved for owners; administrators prepare the
  // engagement and request the authorization.
  const ownerOnly = new Set<Capability>(['engagement.authorize']);
  for (const capability of CAPABILITIES) {
    const owner = can('OWNER', capability);
    const admin = can('ADMIN', capability);
    assert.equal(admin && !owner, false, `${capability} is granted to ADMIN but not OWNER`);
    assert.equal(
      owner && !admin,
      ownerOnly.has(capability),
      `${capability} is owner-only but not declared`,
    );
  }
});

test('every capability is either mutating or read-only, never both', () => {
  for (const capability of CAPABILITIES) {
    if (isMutating(capability)) {
      assert.equal(
        capability.endsWith('.read'),
        false,
        `${capability} is read-only but marked mutating`,
      );
    }
  }
  assert.equal(MUTATING_CAPABILITIES.size > 0, true);
});

test('second factor is required only for privileged mutating actions', () => {
  assert.equal(requiresSecondFactor('OWNER', 'asset.create'), true);
  assert.equal(requiresSecondFactor('ADMIN', 'finding.import'), true);
  assert.equal(requiresSecondFactor('OWNER', 'audit.read'), false);
  assert.equal(requiresSecondFactor('ANALYST', 'asset.create'), false);
  assert.equal(requiresSecondFactor('VIEWER', 'asset.create'), false);
});

test('role helpers reject unknown roles', () => {
  assert.equal(isOrgRole('OWNER'), true);
  assert.equal(isOrgRole('owner'), false);
  assert.equal(isOrgRole(undefined), false);

  // An unexpected role string must never fall through to a granted capability.
  assert.equal(can('SUPERUSER' as OrgRole, 'asset.delete'), false);
});

test('role ordering matches the documented hierarchy', () => {
  assert.equal(isAtLeast('OWNER', 'ADMIN'), true);
  assert.equal(isAtLeast('ADMIN', 'ADMIN'), true);
  assert.equal(isAtLeast('ANALYST', 'ADMIN'), false);
  assert.equal(isAtLeast('VIEWER', 'VIEWER'), true);
  assert.deepEqual(ORG_ROLES, ['OWNER', 'ADMIN', 'ANALYST', 'VIEWER']);
});
