import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { verifyAuditChain } from '@/server/audit/audit';
import { adoptFramework } from '@/server/services/compliance';
import {
  deleteEvidenceFile,
  listEvidenceFiles,
  sweepEvidenceIntegrity,
  uploadEvidenceFile,
  verifyEvidenceFile,
} from '@/server/services/evidence-files';
import { blobPath, evidenceRoot } from '@/server/services/evidence-storage';
import {
  assertTestDatabase,
  createTenant,
  expectAppError,
  prisma,
  resetDatabase,
} from './helpers/database.ts';

/**
 * File-backed evidence is only worth something if "unchanged since upload" is
 * checkable, so these tests exercise the property end to end against the real
 * filesystem: the recorded hash, a verification that passes, one that fails after
 * a byte changes on disk, and one that reports a deleted artifact as missing.
 */

const BODY = 'control evidence: MFA enforced for all administrators\n';

let root: string;

before(async () => {
  assertTestDatabase();
  root = mkdtempSync(join(tmpdir(), 'cn-evidence-'));
  process.env.EVIDENCE_DIR = root;
  await resetDatabase();
});

after(() => {
  delete process.env.EVIDENCE_DIR;
  rmSync(root, { recursive: true, force: true });
});

function stream(text: string): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

type Tenant = Awaited<ReturnType<typeof createTenant>>;

async function controlFor(tenant: Tenant): Promise<string> {
  await adoptFramework(tenant.ctx, { frameworkId: 'SOC2' });
  const adoption = await prisma.organizationFramework.findFirstOrThrow({
    where: { organizationId: tenant.organization.id },
    select: { id: true },
  });
  const control = await prisma.organizationControl.findFirstOrThrow({
    where: { organizationFrameworkId: adoption.id },
    select: { id: true },
  });
  return control.id;
}

test('upload stores the bytes, records the hash, and never trusts the file name', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const organizationControlId = await controlFor(tenant);
  const capturedAt = new Date('2026-10-01T09:30:00.000Z');

  const file = await uploadEvidenceFile(tenant.ctx, organizationControlId, {
    fileName: '../../etc/evidence.txt',
    contentType: 'text/plain',
    capturedAt,
    note: 'Quarterly access review output',
    body: stream(BODY),
    declaredLength: Buffer.byteLength(BODY),
  });

  assert.equal(file.sha256, createHash('sha256').update(BODY).digest('hex'));
  assert.equal(file.sizeBytes, Buffer.byteLength(BODY));
  assert.equal(file.integrityStatus, 'UNVERIFIED');
  assert.equal(file.integrityCheckedAt, null);
  assert.equal(file.capturedAt, capturedAt.toISOString(), 'capture time is the uploader statement');
  assert.equal(file.fileName.includes('/'), false, 'the stored name must not carry a path');

  const row = await prisma.controlEvidence.findUniqueOrThrow({
    where: { id: file.id },
    select: { kind: true, blobKey: true, sha256: true, organizationId: true },
  });
  assert.equal(row.kind, 'FILE');
  assert.equal(row.organizationId, tenant.organization.id);
  assert.ok(row.blobKey);

  const stored = readFileSync(blobPath(root, row.blobKey));
  assert.deepEqual(stored, Buffer.from(BODY), 'the bytes on disk are the bytes received');

  const audit = await prisma.auditEvent.findFirstOrThrow({
    where: { organizationId: tenant.organization.id, action: 'compliance.evidence_file_uploaded' },
    select: { metadata: true },
  });
  assert.equal(
    (audit.metadata as { sha256?: string }).sha256,
    file.sha256,
    'the chain holds the hash even if the row is later altered',
  );

  // A type outside the allow-list is refused before anything is written.
  await expectAppError(
    uploadEvidenceFile(tenant.ctx, organizationControlId, {
      fileName: 'payload.html',
      contentType: 'text/html',
      body: stream('<script>alert(1)</script>'),
    }),
    { statusCode: 400 },
  );
  assert.equal(
    await prisma.controlEvidence.count({
      where: { organizationId: tenant.organization.id, kind: 'FILE' },
    }),
    1,
  );
});

test('verification proves the file unchanged, and detects a changed byte', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const organizationControlId = await controlFor(tenant);

  const file = await uploadEvidenceFile(tenant.ctx, organizationControlId, {
    fileName: 'screenshot.png',
    contentType: 'image/png',
    body: stream(BODY),
  });

  const intact = await verifyEvidenceFile(tenant.ctx, file.id);
  assert.equal(intact.outcome, 'INTACT');
  assert.equal(intact.actualSha256, file.sha256);

  const row = await prisma.controlEvidence.findUniqueOrThrow({
    where: { id: file.id },
    select: { integrityStatus: true, integrityCheckedAt: true, blobKey: true },
  });
  assert.equal(row.integrityStatus, 'INTACT');
  assert.ok(row.integrityCheckedAt);
  assert.ok(row.blobKey);

  // Same length, different content: a size-only check would miss this.
  const tampered = `${BODY.slice(0, -2)}X\n`;
  assert.equal(Buffer.byteLength(tampered), Buffer.byteLength(BODY));
  writeFileSync(blobPath(root, row.blobKey), tampered);

  const mismatch = await verifyEvidenceFile(tenant.ctx, file.id);
  assert.equal(mismatch.outcome, 'MISMATCH');
  assert.notEqual(mismatch.actualSha256, file.sha256);

  const failed = await prisma.auditEvent.findFirstOrThrow({
    where: {
      organizationId: tenant.organization.id,
      action: 'compliance.evidence_integrity_checked',
      outcome: 'FAILURE',
    },
    select: { metadata: true },
  });
  assert.equal((failed.metadata as { outcome?: string }).outcome, 'MISMATCH');

  const refreshed = await prisma.controlEvidence.findUniqueOrThrow({
    where: { id: file.id },
    select: { integrityStatus: true },
  });
  assert.equal(refreshed.integrityStatus, 'MISMATCH', 'a failed check is recorded, not hidden');
  assert.equal((await verifyAuditChain(tenant.organization.id)).valid, true);
});

test('a deleted artifact is reported missing rather than assumed intact', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const organizationControlId = await controlFor(tenant);

  const file = await uploadEvidenceFile(tenant.ctx, organizationControlId, {
    fileName: 'policy.pdf',
    contentType: 'application/pdf',
    body: stream(BODY),
  });

  const row = await prisma.controlEvidence.findUniqueOrThrow({
    where: { id: file.id },
    select: { blobKey: true },
  });
  assert.ok(row.blobKey);
  rmSync(blobPath(root, row.blobKey));

  const missing = await verifyEvidenceFile(tenant.ctx, file.id);
  assert.equal(missing.outcome, 'MISSING');
  assert.equal(missing.actualSha256, null);
});

test('files are tenant-scoped and the sweep reports what it checked', async () => {
  const owner = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const intruder = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const organizationControlId = await controlFor(owner);

  const file = await uploadEvidenceFile(owner.ctx, organizationControlId, {
    fileName: 'inventory.csv',
    contentType: 'text/csv',
    body: stream(BODY),
  });

  await expectAppError(verifyEvidenceFile(intruder.ctx, file.id), { statusCode: 404 });
  await expectAppError(listEvidenceFiles(intruder.ctx, organizationControlId), { statusCode: 404 });

  const listed = await listEvidenceFiles(owner.ctx, organizationControlId);
  assert.deepEqual(
    listed.map((entry) => entry.id),
    [file.id],
  );

  const sweep = await sweepEvidenceIntegrity({ organizationId: owner.organization.id });
  assert.deepEqual(sweep, { checked: 1, intact: 1, mismatched: 0, missing: 0, skipped: 0 });

  const removed = await deleteEvidenceFile(owner.ctx, file.id);
  assert.equal(removed.blobRemoved, true);
  assert.equal(
    await prisma.controlEvidence.count({ where: { organizationId: owner.organization.id } }),
    0,
  );

  assert.ok(evidenceRoot());
});
