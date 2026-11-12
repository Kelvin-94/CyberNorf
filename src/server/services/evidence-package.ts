import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { Prisma } from '@/generated/prisma/client';
import type { TenantContext } from '@/server/authz/context';
import { AuditActions, recordAuditEvent, verifyAuditChain } from '@/server/audit/audit';
import { canonicalize } from '@/server/audit/canonical';
import {
  getEvidenceSigningKey,
  hasEvidenceSigningKey,
  type EvidenceSigningKey,
} from '@/server/config';
import { AppError } from '@/server/errors';
import { exportOrganization, type OrganizationExport } from './export';

/**
 * Portable, signed evidence package.
 *
 * The interactive export in `export.ts` is a JSON document for a human or an
 * importer. An evidence package is the same data plus three things an auditor
 * needs to trust a copy that has left the platform:
 *
 * 1. a per-document SHA-256 digest, so a changed byte is detectable;
 * 2. an HMAC-SHA256 signature over a canonical manifest, so the digests
 *    themselves cannot be rewritten by whoever holds the file;
 * 3. the audit-chain head and verdict at signing time, so the receiver can see
 *    which chain state the signature covers.
 *
 * Canonicalisation is the same serializer the audit chain uses: keys sorted,
 * no whitespace. A verifier therefore does not need this codebase to check the
 * signature, only the documented algorithm and the shared key.
 */

/**
 * A deployment without a signing key still runs; only package export is off.
 * The route answers 503 with this message instead of a generic 500, because a
 * missing secret is a configuration state an operator can fix.
 */
export class EvidenceSigningUnavailableError extends AppError {
  constructor() {
    super(
      503,
      'INTERNAL_ERROR',
      'Evidence package signing is not configured on this deployment, so signed packages are unavailable.',
    );
  }
}

export const EVIDENCE_PACKAGE_FORMAT = 'cybernorf.evidence-package';
export const EVIDENCE_PACKAGE_VERSION = 1;
export const EVIDENCE_EXPORT_PATH = 'organization-export.json';

export interface EvidencePackageDocument {
  path: string;
  contentType: string;
  bytes: number;
  sha256: string;
}

export interface EvidencePackageManifest {
  format: typeof EVIDENCE_PACKAGE_FORMAT;
  version: number;
  packageId: string;
  createdAt: string;
  organization: { id: string; name: string; slug: string };
  algorithm: 'HMAC-SHA256';
  keyId: string;
  signedBy: { type: 'USER'; id: string };
  documents: EvidencePackageDocument[];
  auditChain: { valid: boolean; checked: number; headHash: string | null };
}

export interface EvidencePackage {
  manifest: EvidencePackageManifest;
  /** Hex HMAC-SHA256 over `canonicalize(manifest)`. */
  signature: string;
  documents: Record<string, unknown>;
}

export interface EvidencePackageVerification {
  valid: boolean;
  reason?:
    | 'format_mismatch'
    | 'version_unsupported'
    | 'key_id_mismatch'
    | 'document_missing'
    | 'document_undeclared'
    | 'document_digest_mismatch'
    | 'document_size_mismatch'
    | 'signature_mismatch'
    | 'audit_chain_invalid';
  documents: Array<{ path: string; ok: boolean }>;
}

/** Serialised bytes that both signing and verification digest. */
export function documentBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

export function digestDocument(value: unknown): { sha256: string; bytes: number } {
  const bytes = documentBytes(value);
  return { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
}

export function signManifest(manifest: EvidencePackageManifest, key: EvidenceSigningKey): string {
  return createHmac('sha256', key.secret).update(canonicalize(manifest), 'utf8').digest('hex');
}

function safeEqualHex(left: string, right: string): boolean {
  const a = Buffer.from(left, 'hex');
  const b = Buffer.from(right, 'hex');
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

/** The configured key, or a 503 when this deployment has none. */
function configuredSigningKey(): EvidenceSigningKey {
  if (!hasEvidenceSigningKey()) {
    throw new EvidenceSigningUnavailableError();
  }
  return getEvidenceSigningKey();
}

export interface BuildEvidencePackageOptions {
  signingKey?: EvidenceSigningKey;
  now?: Date;
  packageId?: string;
}

/**
 * Builds and signs the package, then records `export.package_signed` with the
 * signature and document digests. The audit row is written after the package is
 * assembled for the same reason the plain export writes its own row afterwards:
 * the file must not claim an event it does not contain.
 */
export async function buildEvidencePackage(
  ctx: TenantContext,
  options: BuildEvidencePackageOptions = {},
): Promise<EvidencePackage> {
  const key = options.signingKey ?? configuredSigningKey();
  const now = options.now ?? new Date();
  const packageId = options.packageId ?? randomUUID();

  const exported: OrganizationExport = await exportOrganization(ctx.organization.id);
  const chain = await verifyAuditChain(ctx.organization.id);
  const auditEvents = exported.auditEvents as Array<{ hash?: string }>;
  const headHash =
    auditEvents.length > 0 ? (auditEvents[auditEvents.length - 1]?.hash ?? null) : null;

  const documents: Record<string, unknown> = { [EVIDENCE_EXPORT_PATH]: exported };
  const manifest: EvidencePackageManifest = {
    format: EVIDENCE_PACKAGE_FORMAT,
    version: EVIDENCE_PACKAGE_VERSION,
    packageId,
    createdAt: now.toISOString(),
    organization: {
      id: exported.meta.organization.id,
      name: exported.meta.organization.name,
      slug: exported.meta.organization.slug,
    },
    algorithm: 'HMAC-SHA256',
    keyId: key.keyId,
    signedBy: { type: 'USER', id: ctx.user.id },
    documents: Object.entries(documents).map(([path, value]) => ({
      path,
      contentType: 'application/json',
      ...digestDocument(value),
    })),
    auditChain: { valid: chain.valid, checked: chain.checked, headHash },
  };
  const signature = signManifest(manifest, key);

  await recordAuditEvent({
    organizationId: ctx.organization.id,
    actorType: 'USER',
    actorId: ctx.user.id,
    action: AuditActions.EXPORT_PACKAGE_SIGNED,
    outcome: 'SUCCESS',
    targetType: 'organization',
    targetId: ctx.organization.id,
    summary: `Signed evidence package ${packageId}`,
    metadata: {
      packageId,
      keyId: key.keyId,
      signature,
      documents: manifest.documents,
      auditChain: manifest.auditChain,
    } as unknown as Prisma.InputJsonValue,
    ipAddress: ctx.meta.ipAddress,
    userAgent: ctx.meta.userAgent,
    requestId: ctx.meta.requestId,
  });

  return { manifest, signature, documents };
}

/**
 * Verification is deliberately independent of the database: it takes the file
 * and the shared key. An auditor holding an exported copy can run this without
 * access to the tenant.
 */
export function verifyEvidencePackage(
  pkg: EvidencePackage,
  key: EvidenceSigningKey,
): EvidencePackageVerification {
  const documents: Array<{ path: string; ok: boolean }> = [];

  if (!pkg || typeof pkg !== 'object' || !pkg.manifest) {
    return { valid: false, reason: 'format_mismatch', documents };
  }
  const manifest = pkg.manifest;
  if (manifest.format !== EVIDENCE_PACKAGE_FORMAT) {
    return { valid: false, reason: 'format_mismatch', documents };
  }
  if (manifest.version !== EVIDENCE_PACKAGE_VERSION) {
    return { valid: false, reason: 'version_unsupported', documents };
  }
  if (manifest.keyId !== key.keyId) {
    return { valid: false, reason: 'key_id_mismatch', documents };
  }

  const declared = new Set<string>();
  for (const doc of manifest.documents) {
    declared.add(doc.path);
    const value = pkg.documents?.[doc.path];
    if (value === undefined) {
      documents.push({ path: doc.path, ok: false });
      return { valid: false, reason: 'document_missing', documents };
    }
    const digest = digestDocument(value);
    if (digest.bytes !== doc.bytes) {
      documents.push({ path: doc.path, ok: false });
      return { valid: false, reason: 'document_size_mismatch', documents };
    }
    if (digest.sha256 !== doc.sha256) {
      documents.push({ path: doc.path, ok: false });
      return { valid: false, reason: 'document_digest_mismatch', documents };
    }
    documents.push({ path: doc.path, ok: true });
  }

  for (const path of Object.keys(pkg.documents ?? {})) {
    if (!declared.has(path)) {
      return { valid: false, reason: 'document_undeclared', documents };
    }
  }

  const expected = signManifest(manifest, key);
  if (!safeEqualHex(expected, pkg.signature)) {
    return { valid: false, reason: 'signature_mismatch', documents };
  }

  if (!manifest.auditChain.valid) {
    return { valid: false, reason: 'audit_chain_invalid', documents };
  }

  return { valid: true, documents };
}
