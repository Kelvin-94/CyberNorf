import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { authenticateAgentToken, recordAgentRun, registerAgent } from '@/server/services/agents';
import {
  importAdvisories,
  listAdvisories,
  listAgentInventory,
  matchPackages,
} from '@/server/services/software';
import { advisoryImportSchema } from '@/server/validation/software';
import {
  assertTestDatabase,
  createTenant,
  prisma,
  resetDatabase,
} from './helpers/database.ts';

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

const CROSS_SPAWN_ADVISORY = {
  identifier: 'CVE-2024-21538',
  packageName: 'cross-spawn',
  ecosystem: 'NPM' as const,
  summary: 'ReDoS when parsing a crafted argument',
  severity: 'HIGH' as const,
  affectedRange: '>= 7.0.0, < 7.0.5',
  fixedVersion: '7.0.5',
  cvssScore: 7.5,
  referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21538',
};

function inventoryReport(version: string, extra: Array<{ ecosystem: 'NPM' | 'BREW'; name: string; version: string }> = []) {
  return {
    hostname: 'kelvins-imac',
    platform: 'darwin 25.6.0',
    startedAt: new Date(Date.now() - 1000),
    durationMs: 1000,
    checks: [
      {
        id: 'vuln.filevault',
        title: 'Full-disk encryption is enabled',
        status: 'PASS' as const,
        severity: 'MEDIUM' as const,
      },
    ],
    inventory: [{ ecosystem: 'NPM' as const, name: 'cross-spawn', version }, ...extra],
  };
}

test('an advisory with an unevaluable range is rejected at import', () => {
  const result = advisoryImportSchema.safeParse({
    advisories: [{ ...CROSS_SPAWN_ADVISORY, affectedRange: '>= banana' }],
  });
  assert.equal(result.success, false);
  const messages = result.success ? [] : result.error.issues.map((issue) => issue.message);
  assert.ok(
    messages.some((message) => message.includes('version range')),
    `expected a range message, got ${JSON.stringify(messages)}`,
  );

  const duplicated = advisoryImportSchema.safeParse({
    advisories: [CROSS_SPAWN_ADVISORY, CROSS_SPAWN_ADVISORY],
  });
  assert.equal(duplicated.success, false, 'the same identifier and package cannot repeat');

  const valid = advisoryImportSchema.safeParse({ advisories: [CROSS_SPAWN_ADVISORY] });
  assert.equal(valid.success, true);
});

test('re-importing the same advisory updates it instead of duplicating', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const first = await importAdvisories(tenant.ctx, { advisories: [CROSS_SPAWN_ADVISORY] });
  assert.deepEqual(first, { created: 1, updated: 0, total: 1 });

  const second = await importAdvisories(tenant.ctx, {
    advisories: [{ ...CROSS_SPAWN_ADVISORY, summary: 'ReDoS with a corrected summary' }],
  });
  assert.deepEqual(second, { created: 0, updated: 1, total: 1 });

  const rows = await prisma.advisory.findMany({
    where: { organizationId: tenant.organization.id },
    select: { summary: true, fixedVersion: true, createdById: true },
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.summary, 'ReDoS with a corrected summary');
  assert.equal(rows[0]?.fixedVersion, '7.0.5');
  assert.equal(rows[0]?.createdById, tenant.user.id);

  const audits = await prisma.auditEvent.count({
    where: { organizationId: tenant.organization.id, action: 'advisory.imported' },
  });
  assert.equal(audits, 2);

  const listed = await listAdvisories(tenant.ctx, { page: 1, pageSize: 10 });
  assert.equal(listed.total, 1);
  assert.equal(listed.items[0]?.identifier, 'CVE-2024-21538');

  // Another organization's feed is never visible.
  const other = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const elsewhere = await listAdvisories(other.ctx, { page: 1, pageSize: 10 });
  assert.equal(elsewhere.total, 0);
});

test('an affected package raises one finding per advisory and host, then refreshes it', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  await importAdvisories(tenant.ctx, { advisories: [CROSS_SPAWN_ADVISORY] });

  const registration = await registerAgent(tenant.ctx, { name: 'inventory-agent', source: 'BUILTIN' });
  const principal = await authenticateAgentToken(
    registration.token ?? assert.fail('expected a builtin token'),
  );

  const first = await recordAgentRun(principal, inventoryReport('7.0.4'));
  assert.equal(first.inventoryCount, 1);
  assert.equal(first.advisoryMatches, 1);
  assert.equal(first.findingsCreated, 1);

  const findings = await prisma.finding.findMany({
    where: { organizationId: tenant.organization.id, source: 'AGENT' },
    select: {
      id: true,
      title: true,
      severity: true,
      status: true,
      cveId: true,
      cvssScore: true,
      remediation: true,
      assetId: true,
      fingerprint: true,
    },
  });
  assert.equal(findings.length, 1);
  const finding = findings[0] ?? assert.fail('expected a finding');
  assert.match(finding.title, /cross-spawn 7\.0\.4 is affected by CVE-2024-21538/);
  assert.equal(finding.severity, 'HIGH');
  assert.equal(finding.status, 'OPEN');
  assert.equal(finding.cveId, 'CVE-2024-21538');
  assert.equal(Number(finding.cvssScore), 7.5);
  assert.match(finding.remediation ?? '', /7\.0\.5 or later/);
  assert.ok(finding.assetId, 'the finding must land on the discovered host asset');

  // The host asset is created once, from the hostname in the report.
  const assets = await prisma.asset.findMany({
    where: { organizationId: tenant.organization.id },
    select: { name: true, identifier: true, type: true },
  });
  assert.equal(assets.length, 1);
  assert.equal(assets[0]?.identifier, 'kelvins-imac');
  assert.equal(assets[0]?.type, 'HOSTNAME');

  const audit = await prisma.auditEvent.findFirst({
    where: {
      organizationId: tenant.organization.id,
      action: 'finding.created',
      actorType: 'AGENT',
    },
    select: { metadata: true },
  });
  const metadata = (audit?.metadata ?? {}) as Record<string, unknown>;
  assert.equal(metadata.advisoryIdentifier, 'CVE-2024-21538');
  assert.equal(metadata.installedVersion, '7.0.4');

  const inventory = await listAgentInventory(tenant.ctx, registration.agent.id);
  assert.equal(inventory.total, 1);
  assert.deepEqual(inventory.items[0]?.affectedBy, ['CVE-2024-21538']);

  const second = await recordAgentRun(principal, inventoryReport('7.0.4'));
  assert.equal(second.findingsCreated, 0);
  assert.equal(second.findingsRefreshed, 1);
  assert.equal(
    await prisma.finding.count({ where: { organizationId: tenant.organization.id } }),
    1,
    'a repeated run must refresh the advisory finding, not duplicate it',
  );

  // Upgrading past the fixed version updates the snapshot and stops matching.
  const third = await recordAgentRun(principal, inventoryReport('7.0.5'));
  assert.equal(third.advisoryMatches, 0);
  assert.equal(third.findingsCreated, 0);
  const items = await prisma.softwareItem.findMany({
    where: { agentId: registration.agent.id },
    select: { version: true, assetId: true },
  });
  assert.equal(items.length, 1);
  assert.equal(items[0]?.version, '7.0.5');
  assert.ok(items[0]?.assetId, 'the snapshot keeps its asset link');
});

test('packages that disappear from a report leave the snapshot', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const registration = await registerAgent(tenant.ctx, { name: 'pruning-agent', source: 'BUILTIN' });
  const principal = await authenticateAgentToken(
    registration.token ?? assert.fail('expected a builtin token'),
  );

  await recordAgentRun(
    principal,
    inventoryReport('7.0.4', [{ ecosystem: 'BREW', name: 'openssl@3', version: '3.5.0' }]),
  );
  assert.equal(
    await prisma.softwareItem.count({ where: { agentId: registration.agent.id } }),
    2,
  );

  await recordAgentRun(principal, inventoryReport('7.0.4'));
  const remaining = await prisma.softwareItem.findMany({
    where: { agentId: registration.agent.id },
    select: { name: true },
  });
  assert.deepEqual(
    remaining.map((row) => row.name),
    ['cross-spawn'],
  );
});

test('matching is per ecosystem and tolerant of package-name casing only', () => {
  const advisory = {
    id: 'adv-1',
    identifier: 'CVE-2024-21538',
    packageName: 'cross-spawn',
    ecosystem: 'NPM' as const,
    summary: 'ReDoS',
    severity: 'HIGH' as const,
    affectedRange: '>= 7.0.0, < 7.0.5',
    fixedVersion: '7.0.5',
    cvssScore: 7.5,
    referenceUrl: null,
  };

  const wrongEcosystem = matchPackages([advisory], [
    { ecosystem: 'BREW', name: 'cross-spawn', version: '7.0.4' },
  ]);
  assert.equal(wrongEcosystem.length, 0, 'a package from another ecosystem must not match');

  const cased = matchPackages([advisory], [
    { ecosystem: 'NPM', name: 'Cross-Spawn', version: '7.0.4' },
  ]);
  assert.equal(cased.length, 1);

  const fixed = matchPackages([advisory], [
    { ecosystem: 'NPM', name: 'cross-spawn', version: '7.0.5' },
  ]);
  assert.equal(fixed.length, 0, 'a fixed version must not match');
});
