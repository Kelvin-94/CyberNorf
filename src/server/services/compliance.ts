import type { ControlStatus, Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  attestationIssue,
  computePosture,
  isAttested,
  type Posture,
} from '@/server/domain/compliance';
import { conflict, notFound } from '@/server/errors';
import {
  assertActiveMember,
  assertAssetInOrganization,
  assertIncidentInOrganization,
  isUniqueConstraintError,
} from './shared';

/**
 * Compliance service.
 *
 * The framework catalog is global and read-only; everything else is scoped to
 * one organization. Every tenant lookup goes through an explicit
 * `organizationId` filter so a guessed identifier from another tenant resolves
 * as "not found" instead of leaking existence.
 */

const EVIDENCE_SELECT = {
  id: true,
  kind: true,
  reference: true,
  note: true,
  createdAt: true,
  createdBy: { select: { id: true, name: true } },
  finding: { select: { id: true, title: true, severity: true, status: true } },
  incident: { select: { id: true, title: true, status: true } },
  asset: { select: { id: true, name: true, identifier: true } },
} satisfies Prisma.ControlEvidenceSelect;

const FRAMEWORK_SUMMARY_SELECT = {
  id: true,
  code: true,
  name: true,
  version: true,
  description: true,
  controls: { select: { id: true, weight: true } },
} satisfies Prisma.FrameworkSelect;

export interface FrameworkCard {
  id: string;
  code: string;
  name: string;
  version: string;
  description: string | null;
  controlCount: number;
  totalWeight: number;
  adopted: boolean;
  adoptedAt: Date | null;
  targetDate: Date | null;
  posture: Posture | null;
}

function totalWeight(controls: ReadonlyArray<{ weight: number }>): number {
  return controls.reduce((sum, control) => sum + control.weight, 0);
}

/**
 * Catalog frameworks with this tenant's adoption state. A framework that has
 * not been adopted has no posture: scoring an untouched catalog would read as
 * 0% and imply a failure the tenant never signed up for.
 */
export async function listFrameworks(organizationId: string): Promise<FrameworkCard[]> {
  const [frameworks, adoptions] = await Promise.all([
    prisma.framework.findMany({
      select: FRAMEWORK_SUMMARY_SELECT,
      orderBy: { code: 'asc' },
    }),
    prisma.organizationFramework.findMany({
      where: { organizationId },
      select: {
        id: true,
        frameworkId: true,
        adoptedAt: true,
        targetDate: true,
        controls: { select: { controlId: true, status: true } },
      },
    }),
  ]);

  const adoptionByFramework = new Map(adoptions.map((row) => [row.frameworkId, row]));

  return frameworks.map((framework) => {
    const adoption = adoptionByFramework.get(framework.id);
    const weightByControl = new Map(framework.controls.map((c) => [c.id, c.weight]));

    return {
      id: framework.id,
      code: framework.code,
      name: framework.name,
      version: framework.version,
      description: framework.description,
      controlCount: framework.controls.length,
      totalWeight: totalWeight(framework.controls),
      adopted: Boolean(adoption),
      adoptedAt: adoption?.adoptedAt ?? null,
      targetDate: adoption?.targetDate ?? null,
      posture: adoption
        ? computePosture(
            adoption.controls.map((control) => ({
              status: control.status,
              weight: weightByControl.get(control.controlId) ?? 1,
            })),
          )
        : null,
    };
  });
}

export interface ComplianceOverview {
  frameworks: FrameworkCard[];
  adopted: number;
  posture: Posture | null;
  /** Attested controls that lost their supporting evidence. */
  integrityWarnings: IntegrityWarning[];
  riskSignals: {
    openCriticalFindings: number;
    openHighFindings: number;
    openIncidents: number;
    controlsDueForReview: number;
  };
  catalogNotice: string;
}

export interface IntegrityWarning {
  frameworkCode: string;
  frameworkName: string;
  organizationControlId: string;
  controlCode: string;
  controlTitle: string;
  message: string;
}

const CATALOG_NOTICE =
  'The bundled catalog is a curated subset of each standard, not the complete ' +
  'control text. It supports internal tracking; it is not a legal opinion or a ' +
  'certification.';

export async function getComplianceOverview(
  ctx: TenantContext,
  now: Date = new Date(),
): Promise<ComplianceOverview> {
  const frameworks = await listFrameworks(ctx.organization.id);
  const adoptedIds = frameworks
    .filter((framework) => framework.adopted)
    .map((framework) => framework.id);

  const [adoptionRows, criticalFindings, highFindings, openIncidents, dueForReview] =
    await Promise.all([
      adoptedIds.length === 0
        ? Promise.resolve(
            [] as Array<{
              frameworkId: string;
              controls: Array<{
                id: string;
                status: ControlStatus;
                lastReviewedAt: Date | null;
                nextReviewAt: Date | null;
                control: { code: string; title: string; weight: number };
                _count: { evidence: number };
              }>;
            }>,
          )
        : prisma.organizationFramework.findMany({
            where: { organizationId: ctx.organization.id, frameworkId: { in: adoptedIds } },
            select: {
              frameworkId: true,
              controls: {
                select: {
                  id: true,
                  status: true,
                  lastReviewedAt: true,
                  nextReviewAt: true,
                  control: { select: { code: true, title: true, weight: true } },
                  _count: { select: { evidence: true } },
                },
              },
            },
          }),
      prisma.finding.count({
        where: {
          organizationId: ctx.organization.id,
          severity: 'CRITICAL',
          status: { in: ['OPEN', 'TRIAGED', 'IN_PROGRESS'] },
        },
      }),
      prisma.finding.count({
        where: {
          organizationId: ctx.organization.id,
          severity: 'HIGH',
          status: { in: ['OPEN', 'TRIAGED', 'IN_PROGRESS'] },
        },
      }),
      prisma.incident.count({
        where: {
          organizationId: ctx.organization.id,
          status: { in: ['OPEN', 'INVESTIGATING', 'CONTAINED'] },
        },
      }),
      prisma.organizationControl.count({
        where: {
          organizationId: ctx.organization.id,
          nextReviewAt: { not: null, lt: now },
        },
      }),
    ]);

  const frameworkName = new Map(frameworks.map((framework) => [framework.id, framework]));

  const everyControl: Array<{ status: ControlStatus; weight: number }> = [];
  const integrityWarnings: IntegrityWarning[] = [];

  for (const adoption of adoptionRows) {
    const framework = frameworkName.get(adoption.frameworkId);
    for (const control of adoption.controls) {
      everyControl.push({ status: control.status, weight: control.control.weight });

      // An attested control with no evidence is reported instead of silently
      // lowering the score: the tenant claims the control works, nothing backs it.
      if (isAttested(control.status) && control._count.evidence === 0) {
        integrityWarnings.push({
          frameworkCode: framework?.code ?? adoption.frameworkId,
          frameworkName: framework?.name ?? adoption.frameworkId,
          organizationControlId: control.id,
          controlCode: control.control.code,
          controlTitle: control.control.title,
          message: `${control.control.code} is ${control.status} without evidence on record.`,
        });
      }
    }
  }

  return {
    frameworks,
    adopted: frameworks.filter((framework) => framework.adopted).length,
    posture: everyControl.length === 0 ? null : computePosture(everyControl),
    integrityWarnings,
    riskSignals: {
      openCriticalFindings: criticalFindings,
      openHighFindings: highFindings,
      openIncidents,
      controlsDueForReview: dueForReview,
    },
    catalogNotice: CATALOG_NOTICE,
  };
}

export interface CatalogControl {
  id: string;
  code: string;
  title: string;
  description: string | null;
  category: string | null;
  weight: number;
  position: number;
}

export interface ControlView extends CatalogControl {
  organizationControlId: string | null;
  status: ControlStatus | null;
  owner: { id: string; name: string; email: string } | null;
  notes: string | null;
  lastReviewedAt: Date | null;
  nextReviewAt: Date | null;
  updatedAt: Date | null;
  evidenceCount: number;
  evidence: Prisma.ControlEvidenceGetPayload<{ select: typeof EVIDENCE_SELECT }>[];
  /** Attested status with no evidence attached. */
  evidenceGap: boolean;
}

export interface FrameworkDetail {
  framework: {
    id: string;
    code: string;
    name: string;
    version: string;
    description: string | null;
    controlCount: number;
    totalWeight: number;
  };
  adoption: {
    id: string;
    adoptedAt: Date;
    targetDate: Date | null;
    adoptedBy: { name: string } | null;
  } | null;
  posture: Posture | null;
  controls: ControlView[];
  integrityWarnings: IntegrityWarning[];
  history: Array<{
    id: string;
    action: string;
    outcome: string;
    summary: string | null;
    metadata: Prisma.JsonValue;
    createdAt: Date;
    actor: { name: string } | null;
  }>;
  catalogNotice: string;
}

async function findFramework(frameworkKey: string) {
  const framework = await prisma.framework.findFirst({
    where: {
      OR: [{ id: frameworkKey }, { code: frameworkKey.trim().toUpperCase() }],
    },
    select: {
      id: true,
      code: true,
      name: true,
      version: true,
      description: true,
      controls: {
        select: {
          id: true,
          code: true,
          title: true,
          description: true,
          category: true,
          weight: true,
          position: true,
        },
        orderBy: [{ position: 'asc' }, { code: 'asc' }],
      },
    },
  });

  if (!framework) {
    throw notFound('Compliance framework not found.');
  }

  return framework;
}

export async function getFrameworkDetail(
  ctx: TenantContext,
  frameworkKey: string,
): Promise<FrameworkDetail> {
  const framework = await findFramework(frameworkKey);

  const adoption = await prisma.organizationFramework.findFirst({
    where: { organizationId: ctx.organization.id, frameworkId: framework.id },
    select: {
      id: true,
      adoptedAt: true,
      targetDate: true,
      adoptedBy: { select: { name: true } },
      controls: {
        select: {
          id: true,
          controlId: true,
          status: true,
          notes: true,
          lastReviewedAt: true,
          nextReviewAt: true,
          updatedAt: true,
          owner: { select: { id: true, name: true, email: true } },
          evidence: { select: EVIDENCE_SELECT, orderBy: { createdAt: 'desc' } },
        },
      },
    },
  });

  const controlState = new Map((adoption?.controls ?? []).map((row) => [row.controlId, row]));

  const controls: ControlView[] = framework.controls.map((control) => {
    const state = controlState.get(control.id);
    const evidence = state?.evidence ?? [];
    return {
      ...control,
      organizationControlId: state?.id ?? null,
      status: state?.status ?? null,
      owner: state?.owner ?? null,
      notes: state?.notes ?? null,
      lastReviewedAt: state?.lastReviewedAt ?? null,
      nextReviewAt: state?.nextReviewAt ?? null,
      updatedAt: state?.updatedAt ?? null,
      evidenceCount: evidence.length,
      evidence,
      evidenceGap: state ? isAttested(state.status) && evidence.length === 0 : false,
    };
  });

  const history = await prisma.auditEvent.findMany({
    where: {
      organizationId: ctx.organization.id,
      targetType: 'compliance_framework',
      targetId: framework.id,
    },
    select: {
      id: true,
      action: true,
      outcome: true,
      summary: true,
      metadata: true,
      createdAt: true,
      actor: { select: { name: true } },
    },
    orderBy: { sequence: 'desc' },
    take: 50,
  });

  return {
    framework: {
      id: framework.id,
      code: framework.code,
      name: framework.name,
      version: framework.version,
      description: framework.description,
      controlCount: framework.controls.length,
      totalWeight: totalWeight(framework.controls),
    },
    adoption: adoption
      ? {
          id: adoption.id,
          adoptedAt: adoption.adoptedAt,
          targetDate: adoption.targetDate,
          adoptedBy: adoption.adoptedBy,
        }
      : null,
    posture: adoption
      ? computePosture(
          adoption.controls.map((row) => ({
            status: row.status,
            weight: framework.controls.find((control) => control.id === row.controlId)?.weight ?? 1,
          })),
        )
      : null,
    controls,
    integrityWarnings: controls
      .filter((control) => control.evidenceGap)
      .map((control) => ({
        frameworkCode: framework.code,
        frameworkName: framework.name,
        organizationControlId: control.organizationControlId ?? '',
        controlCode: control.code,
        controlTitle: control.title,
        message: `${control.code} is ${control.status} without evidence on record.`,
      })),
    history,
    catalogNotice: CATALOG_NOTICE,
  };
}

export interface AdoptFrameworkResult {
  organizationFrameworkId: string;
  frameworkCode: string;
  controlsAdopted: number;
}

/**
 * Adopts a catalog framework for the tenant and opens one attestation row per
 * control at NOT_STARTED. Re-adopting is a conflict rather than a silent reset,
 * because the existing attestations are the tenant's work.
 */
export async function adoptFramework(
  ctx: TenantContext,
  input: { frameworkId: string; targetDate?: Date | null },
): Promise<AdoptFrameworkResult> {
  const framework = await findFramework(input.frameworkId);

  try {
    return await prisma.$transaction(async (tx) => {
      const adoption = await tx.organizationFramework.create({
        data: {
          organizationId: ctx.organization.id,
          frameworkId: framework.id,
          adoptedById: ctx.user.id,
          targetDate: input.targetDate ?? null,
        },
        select: { id: true },
      });

      await tx.organizationControl.createMany({
        data: framework.controls.map((control) => ({
          organizationId: ctx.organization.id,
          organizationFrameworkId: adoption.id,
          controlId: control.id,
          status: 'NOT_STARTED' as const,
        })),
      });

      await appendAuditEvent(tx, {
        organizationId: ctx.organization.id,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.COMPLIANCE_FRAMEWORK_ADOPTED,
        outcome: 'SUCCESS',
        targetType: 'compliance_framework',
        targetId: framework.id,
        summary: `Adopted ${framework.name} (${framework.code})`,
        metadata: {
          frameworkCode: framework.code,
          controlsAdopted: framework.controls.length,
          targetDate: input.targetDate ? input.targetDate.toISOString() : null,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return {
        organizationFrameworkId: adoption.id,
        frameworkCode: framework.code,
        controlsAdopted: framework.controls.length,
      };
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('This framework is already adopted by the organization.');
    }
    throw error;
  }
}

export interface WithdrawFrameworkResult {
  frameworkCode: string;
  controlsRemoved: number;
}

/**
 * Withdraws an adoption. Control evidence is audit material, so the withdrawal
 * is refused while any is attached instead of cascading it away silently.
 */
export async function withdrawFramework(
  ctx: TenantContext,
  frameworkKey: string,
): Promise<WithdrawFrameworkResult> {
  const framework = await findFramework(frameworkKey);

  const adoption = await prisma.organizationFramework.findFirst({
    where: { organizationId: ctx.organization.id, frameworkId: framework.id },
    select: {
      id: true,
      controls: { select: { id: true, _count: { select: { evidence: true } } } },
    },
  });

  if (!adoption) {
    throw notFound('This framework is not adopted by the organization.');
  }

  const controlCount = adoption.controls.length;
  const evidenceCount = adoption.controls.reduce((sum, row) => sum + row._count.evidence, 0);

  if (evidenceCount > 0) {
    throw conflict(
      `Remove the ${evidenceCount} piece(s) of control evidence before withdrawing ${framework.code}.`,
    );
  }

  return prisma.$transaction(async (tx) => {
    await tx.organizationFramework.delete({ where: { id: adoption.id } });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.COMPLIANCE_FRAMEWORK_WITHDRAWN,
      outcome: 'SUCCESS',
      targetType: 'compliance_framework',
      targetId: framework.id,
      summary: `Withdrew ${framework.name} (${framework.code})`,
      metadata: { frameworkCode: framework.code, controlsRemoved: controlCount },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { frameworkCode: framework.code, controlsRemoved: controlCount };
  });
}

export interface UpdateControlResult {
  organizationControlId: string;
  status: ControlStatus;
  previousStatus: ControlStatus;
  evidenceCount: number;
}

/**
 * Updates one attestation. Marking a control IMPLEMENTED requires evidence, and
 * moving into an attested status stamps the review date that the database
 * CHECK constraint requires.
 */
export async function updateControl(
  ctx: TenantContext,
  organizationControlId: string,
  input: Partial<{
    status: ControlStatus;
    ownerId: string | null;
    notes: string | null;
    nextReviewAt: Date | null;
  }>,
): Promise<UpdateControlResult> {
  const existing = await prisma.organizationControl.findFirst({
    where: { id: organizationControlId, organizationId: ctx.organization.id },
    select: {
      id: true,
      status: true,
      ownerId: true,
      notes: true,
      nextReviewAt: true,
      control: { select: { code: true, title: true } },
      organizationFramework: {
        select: { frameworkId: true, framework: { select: { code: true } } },
      },
      _count: { select: { evidence: true } },
    },
  });

  if (!existing) {
    throw notFound('Control not found in this organization.');
  }

  if (input.ownerId !== undefined) {
    await assertActiveMember(ctx.organization.id, input.ownerId);
  }

  const nextStatus = input.status ?? existing.status;
  const evidenceCount = existing._count.evidence;
  const issue = attestationIssue({ status: nextStatus, evidenceCount });
  if (issue) {
    throw conflict(issue);
  }

  const statusChanged = nextStatus !== existing.status;
  const lastReviewedAt = statusChanged && isAttested(nextStatus) ? new Date() : undefined;

  return prisma.$transaction(async (tx) => {
    await tx.organizationControl.update({
      where: { id: existing.id },
      data: {
        ...(input.status !== undefined ? { status: input.status } : {}),
        ...(input.ownerId !== undefined ? { ownerId: input.ownerId } : {}),
        ...(input.notes !== undefined ? { notes: input.notes } : {}),
        ...(input.nextReviewAt !== undefined ? { nextReviewAt: input.nextReviewAt } : {}),
        ...(lastReviewedAt ? { lastReviewedAt } : {}),
        updatedById: ctx.user.id,
      },
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.COMPLIANCE_CONTROL_UPDATED,
      outcome: 'SUCCESS',
      targetType: 'compliance_framework',
      targetId: existing.organizationFramework.frameworkId,
      summary: statusChanged
        ? `${existing.control.code} moved from ${existing.status} to ${nextStatus}`
        : `${existing.control.code} attestation updated`,
      metadata: {
        organizationControlId: existing.id,
        controlCode: existing.control.code,
        frameworkCode: existing.organizationFramework.framework.code,
        statusFrom: existing.status,
        statusTo: nextStatus,
        changedFields: Object.keys(input).sort(),
        evidenceCount,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return {
      organizationControlId: existing.id,
      status: nextStatus,
      previousStatus: existing.status,
      evidenceCount,
    };
  });
}

export interface AddEvidenceInput {
  kind: 'FINDING' | 'INCIDENT' | 'ASSET' | 'REFERENCE';
  findingId?: string | undefined;
  incidentId?: string | undefined;
  assetId?: string | undefined;
  reference?: string | undefined;
  note?: string | null;
}

export interface EvidenceResult {
  id: string;
  organizationControlId: string;
  kind: AddEvidenceInput['kind'];
  evidenceCount: number;
}

export async function addEvidence(
  ctx: TenantContext,
  organizationControlId: string,
  input: AddEvidenceInput,
): Promise<EvidenceResult> {
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

  // The target has to belong to the same tenant; a foreign identifier must not
  // become evidence just because the caller knows it.
  await assertAssetInOrganization(ctx.organization.id, input.assetId ?? null);
  await assertIncidentInOrganization(ctx.organization.id, input.incidentId ?? null);
  if (input.findingId) {
    const finding = await prisma.finding.findFirst({
      where: { id: input.findingId, organizationId: ctx.organization.id },
      select: { id: true },
    });
    if (!finding) {
      throw notFound('Finding not found in this organization.');
    }
  }

  return prisma.$transaction(async (tx) => {
    const evidence = await tx.controlEvidence.create({
      data: {
        organizationId: ctx.organization.id,
        organizationControlId: control.id,
        kind: input.kind,
        findingId: input.kind === 'FINDING' ? (input.findingId ?? null) : null,
        incidentId: input.kind === 'INCIDENT' ? (input.incidentId ?? null) : null,
        assetId: input.kind === 'ASSET' ? (input.assetId ?? null) : null,
        reference: input.kind === 'REFERENCE' ? (input.reference ?? null) : null,
        note: input.note ?? null,
        createdById: ctx.user.id,
      },
      select: { id: true },
    });

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.COMPLIANCE_EVIDENCE_ADDED,
      outcome: 'SUCCESS',
      targetType: 'compliance_framework',
      targetId: control.organizationFramework.frameworkId,
      summary: `Evidence attached to ${control.control.code}`,
      metadata: {
        organizationControlId: control.id,
        controlCode: control.control.code,
        evidenceId: evidence.id,
        kind: input.kind,
        status: control.status,
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return {
      id: evidence.id,
      organizationControlId: control.id,
      kind: input.kind,
      evidenceCount: control._count.evidence + 1,
    };
  });
}

export async function deleteEvidence(
  ctx: TenantContext,
  evidenceId: string,
): Promise<{ id: string; organizationControlId: string }> {
  const evidence = await prisma.controlEvidence.findFirst({
    where: { id: evidenceId, organizationId: ctx.organization.id },
    select: {
      id: true,
      kind: true,
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

  // Removing the last support of a claimed implementation would leave an
  // unsupported attestation, so the status has to be stepped back first.
  if (control.status === 'IMPLEMENTED' && control._count.evidence <= 1) {
    throw conflict(
      `Move ${control.control.code} out of IMPLEMENTED before removing its last piece of evidence.`,
    );
  }

  return prisma.$transaction(async (tx) => {
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
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return { id: evidence.id, organizationControlId: evidence.organizationControlId };
  });
}

export interface ComplianceFormOptions {
  members: Array<{ id: string; name: string; email: string }>;
  findings: Array<{ id: string; title: string; severity: string }>;
  incidents: Array<{ id: string; title: string }>;
  assets: Array<{ id: string; name: string; identifier: string }>;
}

export async function listComplianceFormOptions(
  organizationId: string,
): Promise<ComplianceFormOptions> {
  const [members, findings, incidents, assets] = await Promise.all([
    prisma.membership.findMany({
      where: { organizationId, status: 'ACTIVE' },
      select: { user: { select: { id: true, name: true, email: true } } },
      orderBy: { user: { name: 'asc' } },
      take: 200,
    }),
    prisma.finding.findMany({
      where: { organizationId },
      select: { id: true, title: true, severity: true },
      orderBy: { updatedAt: 'desc' },
      take: 100,
    }),
    prisma.incident.findMany({
      where: { organizationId },
      select: { id: true, title: true },
      orderBy: { createdAt: 'desc' },
      take: 100,
    }),
    prisma.asset.findMany({
      where: { organizationId, status: { not: 'RETIRED' } },
      select: { id: true, name: true, identifier: true },
      orderBy: { name: 'asc' },
      take: 500,
    }),
  ]);

  return {
    members: members.map((membership) => membership.user),
    findings,
    incidents,
    assets,
  };
}
