import { Prisma, type FindingSeverity, type PackageEcosystem } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import { satisfiesRange } from '@/server/domain/versions';
import { notFound } from '@/server/errors';
import {
  advisoryFingerprint,
  isUniqueConstraintError,
  paginationMeta,
} from '@/server/services/shared';
import type {
  AdvisoryInput,
  AdvisoryImportInput,
  SoftwareItemInput,
} from '@/server/validation/software';

/** Advisories loaded for one matching pass; bounded so a run stays cheap. */
const MATCH_ADVISORY_LIMIT = 5000;

const ADVISORY_SELECT = {
  id: true,
  identifier: true,
  packageName: true,
  ecosystem: true,
  summary: true,
  severity: true,
  affectedRange: true,
  fixedVersion: true,
  cvssScore: true,
  referenceUrl: true,
  publishedAt: true,
  createdAt: true,
  updatedAt: true,
} as const satisfies Prisma.AdvisorySelect;

type AdvisoryRow = Prisma.AdvisoryGetPayload<{ select: typeof ADVISORY_SELECT }>;

export interface AdvisoryView {
  id: string;
  identifier: string;
  packageName: string;
  ecosystem: string;
  summary: string;
  severity: string;
  affectedRange: string;
  fixedVersion: string | null;
  cvssScore: number | null;
  referenceUrl: string | null;
  publishedAt: string | null;
  updatedAt: string;
}

function serializeAdvisory(row: AdvisoryRow): AdvisoryView {
  return {
    id: row.id,
    identifier: row.identifier,
    packageName: row.packageName,
    ecosystem: row.ecosystem,
    summary: row.summary,
    severity: row.severity,
    affectedRange: row.affectedRange,
    fixedVersion: row.fixedVersion,
    cvssScore: row.cvssScore === null ? null : Number(row.cvssScore),
    referenceUrl: row.referenceUrl,
    publishedAt: row.publishedAt?.toISOString() ?? null,
    updatedAt: row.updatedAt.toISOString(),
  };
}

export interface AdvisoryListQuery {
  search?: string | undefined;
  ecosystem?: AdvisoryRow['ecosystem'] | undefined;
  page: number;
  pageSize: number;
}

export interface AdvisoryListResult {
  items: AdvisoryView[];
  page: number;
  pageSize: number;
  total: number;
  pageCount: number;
}

/**
 * Advisories are organization-scoped and readable by every role: knowing which
 * packages the fleet is exposed to is investigation, not configuration.
 */
export async function listAdvisories(
  ctx: TenantContext,
  query: AdvisoryListQuery,
): Promise<AdvisoryListResult> {
  const search = query.search?.trim();
  const where: Prisma.AdvisoryWhereInput = {
    organizationId: ctx.organization.id,
    ...(query.ecosystem ? { ecosystem: query.ecosystem } : {}),
    ...(search
      ? {
          OR: [
            { identifier: { contains: search, mode: 'insensitive' } },
            { packageName: { contains: search, mode: 'insensitive' } },
            { summary: { contains: search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.advisory.count({ where }),
    prisma.advisory.findMany({
      where,
      orderBy: [{ identifier: 'asc' }, { packageName: 'asc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
      select: ADVISORY_SELECT,
    }),
  ]);

  return {
    items: rows.map(serializeAdvisory),
    ...paginationMeta(query.page, query.pageSize, total),
  };
}

export interface AdvisoryImportResult {
  created: number;
  updated: number;
  total: number;
}

/**
 * Upserts a batch of advisories in one transaction and records what changed.
 *
 * Import is idempotent on (identifier, package), so re-importing an updated feed
 * corrects existing rows instead of duplicating them, and a run that matches an
 * advisory keeps the same finding identity it had before the re-import.
 */
export async function importAdvisories(
  ctx: TenantContext,
  input: AdvisoryImportInput,
): Promise<AdvisoryImportResult> {
  const created = await prisma.$transaction(async (tx) => {
    const identifiers = [...new Set(input.advisories.map((row) => row.identifier))];
    const existing = await tx.advisory.findMany({
      where: { organizationId: ctx.organization.id, identifier: { in: identifiers } },
      select: { identifier: true, packageName: true },
    });
    const existingKeys = new Set(
      existing.map((row) => `${row.identifier.toLowerCase()}::${row.packageName.toLowerCase()}`),
    );

    let createdCount = 0;
    let updatedCount = 0;
    for (const advisory of input.advisories) {
      const key = `${advisory.identifier.toLowerCase()}::${advisory.packageName.toLowerCase()}`;
      const fields = advisoryFields(advisory);
      await tx.advisory.upsert({
        where: {
          organizationId_identifier_packageName: {
            organizationId: ctx.organization.id,
            identifier: advisory.identifier,
            packageName: advisory.packageName,
          },
        },
        create: {
          ...fields,
          organizationId: ctx.organization.id,
          identifier: advisory.identifier,
          packageName: advisory.packageName,
          createdById: ctx.user.id,
        },
        update: fields,
        select: { id: true },
      });
      if (existingKeys.has(key)) {
        updatedCount += 1;
      } else {
        createdCount += 1;
      }
    }

    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ADVISORY_IMPORTED,
      outcome: 'SUCCESS',
      targetType: 'advisory',
      targetId: null,
      summary: `Imported ${input.advisories.length} advisor${input.advisories.length === 1 ? 'y' : 'ies'} (${createdCount} new, ${updatedCount} updated)`,
      metadata: {
        submitted: input.advisories.length,
        created: createdCount,
        updated: updatedCount,
        identifiers: identifiers.slice(0, 50),
      },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });

    return createdCount;
  });

  return {
    created,
    updated: input.advisories.length - created,
    total: input.advisories.length,
  };
}

interface AdvisoryFields {
  summary: string;
  ecosystem: PackageEcosystem;
  severity: FindingSeverity;
  affectedRange: string;
  fixedVersion: string | null;
  cvssScore: number | null;
  referenceUrl: string | null;
  publishedAt: Date | null;
}

/** Values an import always overwrites, shared by the create and update paths. */
function advisoryFields(advisory: AdvisoryInput): AdvisoryFields {
  return {
    summary: advisory.summary,
    ecosystem: advisory.ecosystem,
    severity: advisory.severity,
    affectedRange: advisory.affectedRange,
    fixedVersion: advisory.fixedVersion ?? null,
    cvssScore: advisory.cvssScore === undefined ? null : advisory.cvssScore,
    referenceUrl: advisory.referenceUrl ?? null,
    publishedAt: advisory.publishedAt ? new Date(advisory.publishedAt) : null,
  };
}

export async function deleteAdvisory(
  ctx: TenantContext,
  advisoryId: string,
): Promise<{ id: string }> {
  const existing = await prisma.advisory.findFirst({
    where: { id: advisoryId, organizationId: ctx.organization.id },
    select: { id: true, identifier: true, packageName: true },
  });
  if (!existing) {
    throw notFound('Advisory not found in this organization.');
  }

  await prisma.$transaction(async (tx) => {
    await tx.advisory.delete({ where: { id: existing.id } });
    await appendAuditEvent(tx, {
      organizationId: ctx.organization.id,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.ADVISORY_DELETED,
      outcome: 'SUCCESS',
      targetType: 'advisory',
      targetId: existing.id,
      summary: `Advisory ${existing.identifier} for ${existing.packageName} removed`,
      metadata: { identifier: existing.identifier, packageName: existing.packageName },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });

  return { id: existing.id };
}

interface PackageForMatching {
  ecosystem: AdvisoryRow['ecosystem'];
  name: string;
  version: string;
}

interface MatchableAdvisory {
  id: string;
  identifier: string;
  packageName: string;
  ecosystem: AdvisoryRow['ecosystem'];
  summary: string;
  severity: AdvisoryRow['severity'];
  affectedRange: string;
  fixedVersion: string | null;
  cvssScore: number | null;
  referenceUrl: string | null;
}

/** Package identity used on both sides of matching, case-insensitively. */
function packageKey(ecosystem: string, name: string): string {
  return `${ecosystem}::${name.trim().toLowerCase()}`;
}

/**
 * Pure matching pass: for every advisory, find the installed package it names
 * and keep it only when the installed version falls inside the affected range.
 * Keeping this separate from persistence makes the decision testable without a
 * database.
 */
export function matchPackages(
  advisories: readonly MatchableAdvisory[],
  packages: readonly PackageForMatching[],
): Array<{ advisory: MatchableAdvisory; package: PackageForMatching }> {
  const byKey = new Map<string, PackageForMatching>();
  for (const pkg of packages) {
    const key = packageKey(pkg.ecosystem, pkg.name);
    if (!byKey.has(key)) {
      byKey.set(key, pkg);
    }
  }

  const matches: Array<{ advisory: MatchableAdvisory; package: PackageForMatching }> = [];
  for (const advisory of advisories) {
    const pkg = byKey.get(packageKey(advisory.ecosystem, advisory.packageName));
    if (!pkg) {
      continue;
    }
    if (!satisfiesRange(pkg.version, advisory.affectedRange)) {
      continue;
    }
    matches.push({ advisory, package: pkg });
  }
  return matches;
}

export interface InventoryMatchInput {
  organizationId: string;
  agentId: string;
  createdById: string;
  hostname: string | null;
  items: readonly SoftwareItemInput[];
}

export interface AdvisoryMatchDraft {
  advisoryId: string;
  identifier: string;
  packageName: string;
  ecosystem: string;
  installedVersion: string;
  severity: AdvisoryRow['severity'];
  summary: string;
  affectedRange: string;
  fixedVersion: string | null;
  cvssScore: number | null;
  referenceUrl: string | null;
  /** Host the finding is reported against, used in the title and description. */
  target: string;
  fingerprint: string;
  assetId: string | null;
}

export interface InventoryMatchResult {
  inventoryCount: number;
  assetId: string | null;
  assetCreated: boolean;
  matches: AdvisoryMatchDraft[];
}

/**
 * Replaces an agent's inventory snapshot and returns the advisories that now
 * apply to it. Findings are not written here: the caller owns finding identity,
 * dedupe and audit so every finding in a run is created the same way.
 */
export async function syncInventoryAndMatch(
  tx: Prisma.TransactionClient,
  input: InventoryMatchInput,
): Promise<InventoryMatchResult> {
  const target = input.hostname?.trim() || 'local';
  const host = input.hostname
    ? await resolveHostAsset(tx, {
        organizationId: input.organizationId,
        hostname: input.hostname,
        createdById: input.createdById,
      })
    : { id: null, created: false };

  const now = new Date();
  const existing = await tx.softwareItem.findMany({
    where: { agentId: input.agentId },
    select: { id: true, ecosystem: true, name: true },
  });
  const existingByKey = new Map(existing.map((row) => [packageKey(row.ecosystem, row.name), row]));

  const seenIds = new Set<string>();
  for (const item of input.items) {
    const match = existingByKey.get(packageKey(item.ecosystem, item.name));
    if (match) {
      seenIds.add(match.id);
      await tx.softwareItem.update({
        where: { id: match.id },
        data: {
          version: item.version,
          lastSeenAt: now,
          // A report without a hostname must not clear an existing asset link.
          ...(host.id ? { assetId: host.id } : {}),
        },
      });
      continue;
    }
    const created = await tx.softwareItem.create({
      data: {
        organizationId: input.organizationId,
        agentId: input.agentId,
        assetId: host.id,
        ecosystem: item.ecosystem,
        name: item.name,
        version: item.version,
        firstSeenAt: now,
        lastSeenAt: now,
      },
      select: { id: true },
    });
    seenIds.add(created.id);
  }

  // A package that is no longer installed must stop being reported, otherwise
  // an uninstalled (or upgraded) package would keep matching advisories.
  const stale = existing.filter((row) => !seenIds.has(row.id)).map((row) => row.id);
  if (stale.length > 0) {
    await tx.softwareItem.deleteMany({ where: { id: { in: stale } } });
  }

  if (input.items.length === 0) {
    return { inventoryCount: 0, assetId: host.id, assetCreated: host.created, matches: [] };
  }

  const names = [...new Set(input.items.map((item) => item.name))];
  const advisories = await tx.advisory.findMany({
    where: {
      organizationId: input.organizationId,
      packageName: { in: names, mode: 'insensitive' },
    },
    take: MATCH_ADVISORY_LIMIT,
    select: {
      id: true,
      identifier: true,
      packageName: true,
      ecosystem: true,
      summary: true,
      severity: true,
      affectedRange: true,
      fixedVersion: true,
      cvssScore: true,
      referenceUrl: true,
    },
  });

  const matched = matchPackages(
    advisories.map((advisory) => ({
      ...advisory,
      cvssScore: advisory.cvssScore === null ? null : Number(advisory.cvssScore),
    })),
    input.items,
  );

  const matches = matched.map(({ advisory, package: pkg }) => ({
    advisoryId: advisory.id,
    identifier: advisory.identifier,
    packageName: advisory.packageName,
    ecosystem: advisory.ecosystem,
    installedVersion: pkg.version,
    severity: advisory.severity,
    summary: advisory.summary,
    affectedRange: advisory.affectedRange,
    fixedVersion: advisory.fixedVersion,
    cvssScore: advisory.cvssScore,
    referenceUrl: advisory.referenceUrl,
    target,
    fingerprint: advisoryFingerprint(
      input.organizationId,
      advisory.identifier,
      advisory.packageName,
      target,
    ),
    assetId: host.id,
  }));

  return {
    inventoryCount: input.items.length,
    assetId: host.id,
    assetCreated: host.created,
    matches,
  };
}

/**
 * Finds (or records) the asset that represents the reporting host, so advisory
 * findings land on a real asset instead of floating without context. The asset
 * is created on first sight with DECLARED verification, matching every other
 * operator-declared asset.
 */
async function resolveHostAsset(
  tx: Prisma.TransactionClient,
  input: { organizationId: string; hostname: string; createdById: string },
): Promise<{ id: string; created: boolean }> {
  const hostname = input.hostname.trim();
  const existing = await tx.asset.findFirst({
    where: {
      organizationId: input.organizationId,
      identifier: { equals: hostname, mode: 'insensitive' },
    },
    select: { id: true },
  });
  if (existing) {
    return { id: existing.id, created: false };
  }

  try {
    const created = await tx.asset.create({
      data: {
        organizationId: input.organizationId,
        name: hostname,
        type: 'HOSTNAME',
        identifier: hostname,
        description: 'Discovered from the inventory reported by a monitoring agent.',
        criticality: 'MEDIUM',
        status: 'ACTIVE',
        verificationStatus: 'DECLARED',
        createdById: input.createdById,
      },
      select: { id: true },
    });
    return { id: created.id, created: true };
  } catch (error) {
    // A concurrent run may have created the same host first; reuse it.
    if (isUniqueConstraintError(error)) {
      const raced = await tx.asset.findFirst({
        where: {
          organizationId: input.organizationId,
          identifier: { equals: hostname, mode: 'insensitive' },
        },
        select: { id: true },
      });
      if (raced) {
        return { id: raced.id, created: false };
      }
    }
    throw error;
  }
}

export interface InventoryItemView {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  firstSeenAt: string;
  lastSeenAt: string;
  assetId: string | null;
  /** True when a current advisory's range covers the installed version. */
  affectedBy: string[];
}

/**
 * Current inventory of one agent, annotated with the advisories that cover it,
 * so the console can show exposure without re-running the matcher.
 */
export async function listAgentInventory(
  ctx: TenantContext,
  agentId: string,
): Promise<{ items: InventoryItemView[]; total: number }> {
  const agent = await prisma.agent.findFirst({
    where: { id: agentId, organizationId: ctx.organization.id },
    select: { id: true },
  });
  if (!agent) {
    throw notFound('Agent not found in this organization.');
  }

  const rows = await prisma.softwareItem.findMany({
    where: { organizationId: ctx.organization.id, agentId },
    orderBy: [{ ecosystem: 'asc' }, { name: 'asc' }],
    take: 1000,
    select: {
      id: true,
      ecosystem: true,
      name: true,
      version: true,
      firstSeenAt: true,
      lastSeenAt: true,
      assetId: true,
    },
  });
  if (rows.length === 0) {
    return { items: [], total: 0 };
  }

  const advisories = await prisma.advisory.findMany({
    where: {
      organizationId: ctx.organization.id,
      packageName: { in: [...new Set(rows.map((row) => row.name))], mode: 'insensitive' },
    },
    take: MATCH_ADVISORY_LIMIT,
    select: {
      identifier: true,
      packageName: true,
      ecosystem: true,
      affectedRange: true,
    },
  });

  const affectedBy = new Map<string, string[]>();
  for (const row of rows) {
    const identifiers = advisories
      .filter(
        (advisory) =>
          packageKey(advisory.ecosystem, advisory.packageName) ===
            packageKey(row.ecosystem, row.name) &&
          satisfiesRange(row.version, advisory.affectedRange),
      )
      .map((advisory) => advisory.identifier);
    if (identifiers.length > 0) {
      affectedBy.set(row.id, identifiers.sort());
    }
  }

  return {
    items: rows.map((row) => ({
      id: row.id,
      ecosystem: row.ecosystem,
      name: row.name,
      version: row.version,
      firstSeenAt: row.firstSeenAt.toISOString(),
      lastSeenAt: row.lastSeenAt.toISOString(),
      assetId: row.assetId,
      affectedBy: affectedBy.get(row.id) ?? [],
    })),
    total: rows.length,
  };
}
