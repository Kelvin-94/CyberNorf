import { readFile } from 'node:fs/promises';
import { getEvidenceSigningKey } from '@/server/config';
import {
  EVIDENCE_PACKAGE_FORMAT,
  verifyEvidencePackage,
  type EvidencePackage,
} from '@/server/services/evidence-package';

/**
 * Offline verifier for a signed evidence package.
 *
 *   EVIDENCE_SIGNING_KEY=... npm run evidence:verify-package -- ./package.json
 *
 * It needs no database and no account: the file plus the shared key are enough
 * to recompute every document digest and the manifest signature. Exit code 1
 * means the package must not be trusted; the reason is printed.
 */

async function main(): Promise<void> {
  const path = process.argv[2];
  if (!path) {
    console.error('Usage: npm run evidence:verify-package -- <path-to-package.json>');
    process.exitCode = 1;
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    console.error(`Could not read ${path} as JSON: ${(error as Error).message}`);
    process.exitCode = 1;
    return;
  }

  const pkg = parsed as EvidencePackage;
  if (!pkg || typeof pkg !== 'object' || pkg.manifest?.format !== EVIDENCE_PACKAGE_FORMAT) {
    console.error(`Not a ${EVIDENCE_PACKAGE_FORMAT} document.`);
    process.exitCode = 1;
    return;
  }

  const configured = getEvidenceSigningKey();
  // The key id travels in the file, so a verifier with one key does not need to
  // know which id the signer used. An explicit environment value still wins.
  const key = {
    keyId: process.env.EVIDENCE_SIGNING_KEY_ID?.trim() || pkg.manifest.keyId || configured.keyId,
    secret: configured.secret,
  };

  const result = verifyEvidencePackage(pkg, key);

  console.log(`Package: ${pkg.manifest.packageId}`);
  console.log(`Organization: ${pkg.manifest.organization.slug} (${pkg.manifest.organization.id})`);
  console.log(`Signed at: ${pkg.manifest.createdAt} by key "${pkg.manifest.keyId}"`);
  for (const doc of result.documents) {
    console.log(`  ${doc.ok ? 'OK  ' : 'FAIL'} ${doc.path}`);
  }
  console.log(
    `Audit chain at signing: ${pkg.manifest.auditChain.valid ? 'valid' : 'INVALID'} (${pkg.manifest.auditChain.checked} event(s))`,
  );

  if (result.valid) {
    console.log('Signature and document digests verified.');
    return;
  }

  console.error(`Verification failed: ${result.reason ?? 'unknown_reason'}`);
  process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
