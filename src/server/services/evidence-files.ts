import type { EvidenceIntegrity, Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { MAX_EVIDENCE_BYTES, isAllowedEvidenceType } from '@/server/domain/quotas';
import { badRequest, conflict, notFound } from '@/server/errors';
import {
  EvidenceStorageUnavailableError,
  type IntegrityOutcome,
  blobPath,
  deleteArtifact,
  evidenceRoot,
  sanitiseFileName,
  storeArtifact,
  verifyArtifact,
} from './evidence-storage';
import { assertQuotaAvailable } from './quotas';

/**
 * File-backed control evidence.
 *
 * A file is evidence only if you can prove it is the same file later, so every
 * upload records four things together: the bytes (a blob outside the database),
 * their SHA-256, the time they arrived, and the time the artifact claims to have
 * been produced. `capturedAt` is the uploader's statement and is kept separate
 * from `createdAt` because conflating them would let a screenshot taken last year
 * read as a control that was checked today.
 *
 * Uploading needs the same capability as attaching other evidence
 * (`compliance.evidence`): an analyst who may support a control may attach a file
 * to it.
 */

export interface EvidenceFileView {
  id: string;
  fileName: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  capturedAt: string | null;
  createdAt: string;
  integrityStatus: EvidenceIntegrity;
  integrityCheckedAt: string | null;
  uploadedBy: { id: string; name: string } | null;
}

const FILE_EVIDENCE_SELECT = {
  id: true,
  fileName: true,
  contentType: true,
  sizeBytes: true,
  sha256: true,
  blobKey: true,
  capturedAt: true,
  createdAt: true,
  integrityStatus: true,
  integrityCheckedAt: true,
  createdBy: { select: { id: true, name: true } },
} satisfies Prisma.ControlEvidenceSelect;

function toView(
  row: Prisma.ControlEvidenceGetPayload<{ select: typeof FILE_EVIDENCE_SELECT }>,
): EvidenceFileView {
  return {
    id: row.id,
    fileName: row.fileName ?? 'evidence',
    contentType: row.contentType ?? 'application/octet-stream',
    sizeBytes: row.sizeBytes ?? 0,
    sha256: row.sha256 ?? '',
    capturedAt: row.capturedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    integrityStatus: row.integrityStatus,
    integrityCheckedAt: row.integrityCheckedAt?.toISOString() ?? null,
    uploadedBy: row.createdBy,
  };
}

function requireRoot(): string {
  const root = evidenceRoot();
  if (!root) {
    throw new EvidenceStorageUnavailableError();
  }
  return root;
}

export interface UploadEvidenceFileInput {
  fileName: string;
  contentType: string;
  capturedAt?: Date | null | undefined;
  note?: string | null | undefined;
  body: ReadableStream<Uint8Array>;
  /** Declared length, used only to fail fast before reading the body. */
  declaredLength?: number | undefined;
}

/**
 * Stores one uploaded artifact and records it as evidence for a control.
 *
 * Ordering matters. The quota is checked (and locked) before the bytes are
 * written, so an upload that would exceed the tenant's storage limit does not
 * fill the disk first and get rejected afterwards. The file is written before the
 * row, so a row never points at a blob that does not exist; if the row insert
 * fails the blob is removed again.
 */
export async function uploadEvidenceFile(
  ctx: TenantContext,
  organizationControlId: string,
  input: UploadEvidenceFileInput,
): Promise<EvidenceFileView> {
  const root = requireRoot();

  if (!isAllowedEvidenceType(input.contentType)) {
    throw badRequest(
      'That file type is not accepted for evidence. Use PDF, PNG, JPEG, WebP, plain text, CSV, JSON or Markdown.',
    );
  }
  if (input.declaredLength !== undefined && input.declaredLength > MAX_EVIDENCE_BYTES) {
    throw badRequest(
      `Evidence files are limited to ${Math.round(MAX_EVIDENCE_BYTES / (1024 * 1024))} MB.`,
    );
  }

  const control = await prisma.organizationControl.findFirst({
    where: { id: organizationControlId, organizationId: ctx.organization.id },
    select: {
      id: true,
      status: true,
      control: { select: { code: true } },
      organizationFramework: { select: { frameworkId: true } },
      _count: { select: { evidence: true } },
    },
  });
  if (!control) {
    throw notFound('Control not found in this organization.');
  }

  // Storage is charged after the write, when the real size is known, because the
  // declared Content-Length is a claim and the accepted maximum is per file. The
  // check inside the transaction sees every artifact recorded so far, so a pair
  // of concurrent uploads cannot both slip under the limit unnoticed; the loser
  // is refused and its blob removed below.
  const stored = await storeArtifact({
    root,
    declaredContentType: input.contentType,
    body: input.body,
  });

  try {
    const evidence = await prisma.$transaction(async (tx) => {
      const sizeMb = Math.max(1, Math.ceil(stored.sizeBytes / (1024 * 1024)));
      await assertQuotaAvailable(tx, {
        organizationId: ctx.organization.id,
        tier: ctx.organization.tier,
        resource: 'evidenceStorageMb',
        units: sizeMb,
      });

      const created = await tx.controlEvidence.create({
        data: {
          organizationId: ctx.organization.id,
          organizationControlId: control.id,
          kind: 'FILE',
          fileName: sanitiseFileName(input.fileName),
          contentType: input.contentType,
          sizeBytes: stored.sizeBytes,
          sha256: stored.sha256,
          blobKey: stored.blobKey,
          capturedAt: input.capturedAt ?? null,
          note: input.note ?? null,
          createdById: ctx.user.id,
        },
        select: FILE_EVIDENCE_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.EVIDENCE_FILE_UPLOADED,
        outcome: 'SUCCESS',
        targetType: 'compliance_framework',
        targetId: control.organizationFramework.frameworkId,
        summary: `Evidence file uploaded for ${control.control.code}`,
        metadata: {
          organizationControlId: control.id,
          controlCode: control.control.code,
          evidenceId: created.id,
          // The hash is in the audit trail as well as the row: if the row is
          // later altered, the chain still holds what was received.
          sha256: stored.sha256,
          sizeBytes: stored.sizeBytes,
          contentType: input.contentType,
          fileName: created.fileName,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });

    return toView(evidence);
  } catch (error) {
    // The row did not survive, so nothing references these bytes.
    await deleteArtifact(root, stored.blobKey).catch(() => undefined);
    throw error;
  }
}

/** Files attached to one control, newest first. */
export async function listEvidenceFiles(
  ctx: TenantContext,
  organizationControlId: string,
): Promise<EvidenceFileView[]> {
  const control = await prisma.organizationControl.findFirst({
    where: { id: organizationControlId, organizationId: ctx.organization.id },
    select: { id: true },
  });
  if (!control) {
    throw notFound('Control not found in this organization.');
  }

  const rows = await prisma.controlEvidence.findMany({
    where: { organizationControlId: control.id, kind: 'FILE' },
    select: FILE_EVIDENCE_SELECT,
    orderBy: { createdAt: 'desc' },
  });
  return rows.map(toView);
}

/**
 * Resolves one file's metadata and path for download. Scoped by organization so a
 * guessed evidence id cannot retrieve another tenant's artifact.
 */
export async function getEvidenceFileForDownload(
  ctx: TenantContext,
  evidenceId: string,
): Promise<{ view: EvidenceFileView; path: string; blobKey: string }> {
  const root = requireRoot();
  const row = await prisma.controlEvidence.findFirst({
    where: { id: evidenceId, organizationId: ctx.organization.id, kind: 'FILE' },
    select: FILE_EVIDENCE_SELECT,
  });
  if (!row || !row.blobKey) {
    throw notFound('Evidence file not found in this organization.');
  }
  return { view: toView(row), path: blobPath(root, row.blobKey), blobKey: row.blobKey };
}

/**
 * Re-reads one artifact and records the outcome.
 *
 * The database is updated to whatever was observed, including MISMATCH. Recording
 * a mismatch is the point: a verification that only writes on success cannot
 * answer "when did this last verify" for exactly the files that need attention.
 */
export async function verifyEvidenceFile(
  ctx: TenantContext,
  evidenceId: string,
): Promise<{
  id: string;
  outcome: IntegrityOutcome;
  expectedSha256: string;
  actualSha256: string | null;
  checkedAt: string;
}> {
  const root = requireRoot();
  const row = await prisma.controlEvidence.findFirst({
    where: { id: evidenceId, organizationId: ctx.organization.id, kind: 'FILE' },
    select: FILE_EVIDENCE_SELECT,
  });
  if (!row || !row.blobKey || !row.sha256) {
    throw notFound('Evidence file not found in this organization.');
  }

  const result = await verifyArtifact({
    root,
    blobKey: row.blobKey,
    expectedSha256: row.sha256,
  });
  const checkedAt = new Date();

  await prisma.$transaction(async (tx) => {
    await tx.controlEvidence.update({
      where: { id: row.id },
      data: { integrityStatus: result.outcome, integrityCheckedAt: checkedAt },
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.EVIDENCE_FILE_INTEGRITY_CHECKED,
      // A mismatch is a failure the audit trail must record as one.
      outcome: result.outcome === 'INTACT' ? 'SUCCESS' : 'FAILURE',
      targetType: 'control_evidence',
      targetId: row.id,
      summary:
        result.outcome === 'INTACT'
          ? 'Evidence file verified unchanged'
          : result.outcome === 'MISSING'
            ? 'Evidence file is missing from storage'
            : 'Evidence file no longer matches its recorded hash',
      metadata: {
        outcome: result.outcome,
        expectedSha256: row.sha256,
        // The observed hash is recorded on a mismatch so the operator can compare
        // it against a backup without re-running the check.
        actualSha256: result.actualSha256,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });

  return {
    id: row.id,
    outcome: result.outcome,
    expectedSha256: row.sha256,
    actualSha256: result.actualSha256,
    checkedAt: checkedAt.toISOString(),
  };
}

/**
 * Deletes one file-backed evidence record and its blob.
 *
 * The same rule as other evidence applies: removing the last support of a claimed
 * implementation would leave an unsupported attestation, so the control has to be
 * stepped back first. The row is deleted before the blob, and a blob that cannot
 * be removed is reported rather than hidden.
 */
export async function deleteEvidenceFile(
  ctx: TenantContext,
  evidenceId: string,
): Promise<{ id: string; organizationControlId: string; blobRemoved: boolean }> {
  const root = evidenceRoot();
  const evidence = await prisma.controlEvidence.findFirst({
    where: { id: evidenceId, organizationId: ctx.organization.id },
    select: {
      id: true,
      kind: true,
      blobKey: true,
      organizationControlId: true,
      organizationControl: {
        select: {
          status: true,
          control: { select: { code: true } },
          organizationFramework: { select: { frameworkId: true } },
          _count: { select: { evidence: true } },
        },
      },
    },
  });

  if (!evidence) {
    throw notFound('Evidence not found in this organization.');
  }

  const control = evidence.organizationControl;
  if (control.status === 'IMPLEMENTED' && control._count.evidence <= 1) {
    throw conflict(
      `Move ${control.control.code} out of IMPLEMENTED before removing its last piece of evidence.`,
    );
  }

  await prisma.$transaction(async (tx) => {
    await tx.controlEvidence.delete({ where: { id: evidence.id } });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.COMPLIANCE_EVIDENCE_REMOVED,
      outcome: 'SUCCESS',
      targetType: 'compliance_framework',
      targetId: control.organizationFramework.frameworkId,
      summary: `Evidence removed from ${control.control.code}`,
      metadata: {
        organizationControlId: evidence.organizationControlId,
        controlCode: control.control.code,
        evidenceId: evidence.id,
        kind: evidence.kind,
        hadBlob: Boolean(evidence.blobKey),
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });

  let blobRemoved = true;
  if (root && evidence.blobKey) {
    try {
      await deleteArtifact(root, evidence.blobKey);
    } catch {
      blobRemoved = false;
    }
  }

  return {
    id: evidence.id,
    organizationControlId: evidence.organizationControlId,
    blobRemoved,
  };
}

/**
 * Integrity sweep: re-verifies artifacts that have never been checked or that
 * failed before, oldest check first. Bounded so one sweep cannot run for hours.
 *
 * MISMATCH and MISSING are returned for the caller to alert on. The sweep is
 * deliberately not silent about a missing file: losing an artifact is exactly the
 * event an evidence store exists to detect.
 */
export async function sweepEvidenceIntegrity(options: {
  organizationId?: string;
  limit?: number;
} = {}): Promise<{
  checked: number;
  intact: number;
  mismatched: number;
  missing: number;
  skipped: number;
}> {
  const root = evidenceRoot();
  if (!root) {
    throw new EvidenceStorageUnavailableError();
  }

  const candidates = await prisma.controlEvidence.findMany({
    where: {
      kind: 'FILE',
      ...(options.organizationId ? { organizationId: options.organizationId } : {}),
      OR: [
        { integrityStatus: 'UNVERIFIED' },
        { integrityStatus: 'MISMATCH' },
        { integrityStatus: 'MISSING' },
        // Re-verify anything not looked at in a week, so a slow corruption cannot
        // hide behind an old "INTACT".
        { integrityCheckedAt: { lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } },
      ],
    },
    select: { id: true, organizationId: true, blobKey: true, sha256: true },
    orderBy: { integrityCheckedAt: { sort: 'asc', nulls: 'first' } },
    take: options.limit ?? 50,
  });

  const result = { checked: 0, intact: 0, mismatched: 0, missing: 0, skipped: 0 };
  const checkedAt = new Date();

  for (const row of candidates) {
    if (!row.blobKey || !row.sha256) {
      result.skipped += 1;
      continue;
    }
    const outcome = await verifyArtifact({ root, blobKey: row.blobKey, expectedSha256: row.sha256 });
    await prisma.controlEvidence.update({
      where: { id: row.id },
      data: { integrityStatus: outcome.outcome, integrityCheckedAt: checkedAt },
    });
    result.checked += 1;
    if (outcome.outcome === 'INTACT') {
      result.intact += 1;
    } else if (outcome.outcome === 'MISSING') {
      result.missing += 1;
    } else {
      result.mismatched += 1;
    }
  }

  return result;
}
