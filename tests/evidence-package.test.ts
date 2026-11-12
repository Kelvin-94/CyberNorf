import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import type { OrganizationExport } from '@/server/services/export';
import {
  EVIDENCE_EXPORT_PATH,
  EvidenceSigningUnavailableError,
  buildEvidencePackage,
  signManifest,
  verifyEvidencePackage,
  type EvidencePackage,
} from '@/server/services/evidence-package';
import {
  assertTestDatabase,
  createTenant,
  prisma,
  resetDatabase,
} from './helpers/database.ts';

const KEY = { keyId: 'test-key-1', secret: 'evidence-test-secret-that-is-long-enough' };

function clone(pkg: EvidencePackage): EvidencePackage {
  return structuredClone(pkg);
}

before(async () => {
  assertTestDatabase();
  await resetDatabase();
});

test('a freshly built package verifies and is recorded in the audit chain', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });

  const pkg = await buildEvidencePackage(tenant.ctx, {
    signingKey: KEY,
    packageId: 'pkg-test-0001',
  });

  assert.equal(pkg.manifest.organization.id, tenant.organization.id);
  assert.equal(pkg.manifest.keyId, KEY.keyId);
  assert.equal(pkg.manifest.documents.length, 1);
  assert.equal(pkg.manifest.documents[0]?.path, EVIDENCE_EXPORT_PATH);
  assert.match(pkg.signature, /^[0-9a-f]{64}$/);

  const verification = verifyEvidencePackage(pkg, KEY);
  assert.equal(verification.valid, true);
  assert.deepEqual(verification.documents, [{ path: EVIDENCE_EXPORT_PATH, ok: true }]);

  const audit = await prisma.auditEvent.findFirst({
    where: { organizationId: tenant.organization.id, action: 'export.package_signed' },
    orderBy: { sequence: 'desc' },
  });
  assert.ok(audit, 'issuing a package is an audited action');
  const metadata = audit.metadata as { packageId?: string; signature?: string } | null;
  assert.equal(metadata?.packageId, 'pkg-test-0001');
  assert.equal(metadata?.signature, pkg.signature);
});

test('a changed document is detected even when its length is unchanged', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const pkg = await buildEvidencePackage(tenant.ctx, { signingKey: KEY });

  const tampered = clone(pkg);
  const doc = tampered.documents[EVIDENCE_EXPORT_PATH] as OrganizationExport;
  const original = doc.meta.organization.name;
  doc.meta.organization.name = (original.startsWith('X') ? 'Y' : 'X') + original.slice(1);

  const verification = verifyEvidencePackage(tampered, KEY);
  assert.equal(verification.valid, false);
  assert.equal(verification.reason, 'document_digest_mismatch');
});

test('a changed manifest breaks the signature', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const pkg = await buildEvidencePackage(tenant.ctx, { signingKey: KEY });

  const tampered = clone(pkg);
  tampered.manifest.packageId = 'pkg-attacker-chosen';

  const verification = verifyEvidencePackage(tampered, KEY);
  assert.equal(verification.valid, false);
  assert.equal(verification.reason, 'signature_mismatch');
});

test('a package signed for another key id is rejected', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const pkg = await buildEvidencePackage(tenant.ctx, { signingKey: KEY });

  const verification = verifyEvidencePackage(pkg, { ...KEY, keyId: 'another-key' });
  assert.equal(verification.valid, false);
  assert.equal(verification.reason, 'key_id_mismatch');
});

test('documents that the manifest does not declare are rejected', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const pkg = await buildEvidencePackage(tenant.ctx, { signingKey: KEY });

  const tampered = clone(pkg);
  tampered.documents['extra.json'] = { injected: true };

  const verification = verifyEvidencePackage(tampered, KEY);
  assert.equal(verification.valid, false);
  assert.equal(verification.reason, 'document_undeclared');
});

test('a correctly signed package still fails when it claims an invalid chain', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const pkg = await buildEvidencePackage(tenant.ctx, { signingKey: KEY });

  // Re-sign after editing the chain verdict so the only remaining objection is
  // the claim itself, not a broken signature.
  const tampered = clone(pkg);
  tampered.manifest.auditChain.valid = false;
  tampered.signature = signManifest(tampered.manifest, KEY);

  const verification = verifyEvidencePackage(tampered, KEY);
  assert.equal(verification.valid, false);
  assert.equal(verification.reason, 'audit_chain_invalid');
});

test('a deployment without a signing key refuses to emit an unsigned package', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const savedKey = process.env.EVIDENCE_SIGNING_KEY;
  delete process.env.EVIDENCE_SIGNING_KEY;
  try {
    await assert.rejects(
      () => buildEvidencePackage(tenant.ctx),
      (error: unknown) => {
        assert.ok(error instanceof EvidenceSigningUnavailableError);
        assert.equal(error.statusCode, 503);
        assert.equal(error.code, 'INTERNAL_ERROR');
        return true;
      },
    );
  } finally {
    if (savedKey === undefined) delete process.env.EVIDENCE_SIGNING_KEY;
    else process.env.EVIDENCE_SIGNING_KEY = savedKey;
  }

  const audit = await prisma.auditEvent.findFirst({
    where: { organizationId: tenant.organization.id, action: 'export.package_signed' },
  });
  assert.equal(audit, null, 'a refused package leaves no signed-export audit event');
});

test('the environment key signs packages when no key is passed in options', async () => {
  const tenant = await createTenant({ role: 'OWNER', twoFactorEnabled: true });
  const savedKey = process.env.EVIDENCE_SIGNING_KEY;
  const savedKeyId = process.env.EVIDENCE_SIGNING_KEY_ID;
  const secret = 'environment-provided-signing-secret-32+';
  process.env.EVIDENCE_SIGNING_KEY = secret;
  process.env.EVIDENCE_SIGNING_KEY_ID = 'env-key';
  try {
    const pkg = await buildEvidencePackage(tenant.ctx, { packageId: 'pkg-test-env' });
    assert.equal(pkg.manifest.keyId, 'env-key');
    assert.equal(verifyEvidencePackage(pkg, { keyId: 'env-key', secret }).valid, true);
  } finally {
    if (savedKey === undefined) delete process.env.EVIDENCE_SIGNING_KEY;
    else process.env.EVIDENCE_SIGNING_KEY = savedKey;
    if (savedKeyId === undefined) delete process.env.EVIDENCE_SIGNING_KEY_ID;
    else process.env.EVIDENCE_SIGNING_KEY_ID = savedKeyId;
  }
});
