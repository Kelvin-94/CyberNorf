import { randomUUID } from 'node:crypto';
import { Prisma } from '@/generated/prisma/client';
import { prisma } from '@/lib/prisma';
import { AuditActions, appendAuditEvent } from '@/server/audit/audit';
import type { TenantContext } from '@/server/authz/context';
import {
  evaluatePolicy,
  type PolicyFactBundle,
  type PolicyOutcome,
  type PolicyRequestFacts,
  type PolicyResourceFacts,
} from '@/server/domain/zero-trust';
import { conflict, notFound } from '@/server/errors';
import type {
  CreatePolicyRuleInput,
  EvaluationRequestInput,
  PolicyDecisionListQuery,
  PolicyRuleListQuery,
  UpdatePolicyRuleInput,
} from '@/server/validation/zero-trust';
import {
  loadPolicyRules,
  resolveDeviceFacts,
  resolveNetworkFacts,
  resolveSubject,
  type NetworkFacts,
} from './policy-facts';
import { isUniqueConstraintError, paginationMeta } from './shared';
import { asRecord, isoOrNull } from './zero-trust-support';

/**
 * The policy decision point.
 *
 * A decision is evaluated from facts resolved server-side and stored with the
 * facts it was made from, so an auditor can recompute it months later instead
 * of taking the caller's word for what was true. Verdicts are recorded in
 * `policy_decisions` rather than the audit log: every network admission is a
 * decision, and the audit chain is for changes to configuration, not for the
 * volume of traffic a decision point sees.
 */

export interface PolicyRuleView {
  id: string;
  name: string;
  description: string | null;
  priority: number;
  effect: 'ALLOW' | 'DENY' | 'STEP_UP' | 'QUARANTINE';
  enabled: boolean;
  conditions: Record<string, unknown>;
  createdById: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface PolicyDecisionView {
  id: string;
  correlationId: string;
  subjectKind: 'USER' | 'DEVICE' | 'IDENTITY';
  subjectId: string;
  subjectLabel: string;
  resourceType: string;
  resourceId: string | null;
  resourceSensitivity: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  action: string;
  verdict: 'ALLOW' | 'DENY' | 'STEP_UP' | 'QUARANTINE';
  riskScore: number;
  matchedRuleId: string | null;
  facts: Record<string, unknown>;
  explanation: Record<string, unknown>;
  createdAt: string;
}

const RULE_SELECT = {
  id: true,
  name: true,
  description: true,
  priority: true,
  effect: true,
  enabled: true,
  conditions: true,
  createdById: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.PolicyRuleSelect;

type RuleRow = Prisma.PolicyRuleGetPayload<{ select: typeof RULE_SELECT }>;

function toRuleView(row: RuleRow): PolicyRuleView {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    priority: row.priority,
    effect: row.effect,
    enabled: row.enabled,
    conditions: asRecord(row.conditions),
    createdById: row.createdById,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const DECISION_SELECT = {
  id: true,
  correlationId: true,
  subjectKind: true,
  subjectId: true,
  subjectLabel: true,
  resourceType: true,
  resourceId: true,
  resourceSensitivity: true,
  action: true,
  verdict: true,
  riskScore: true,
  matchedRuleId: true,
  facts: true,
  explanation: true,
  createdAt: true,
} satisfies Prisma.PolicyDecisionSelect;

type DecisionRow = Prisma.PolicyDecisionGetPayload<{ select: typeof DECISION_SELECT }>;

function toDecisionView(row: DecisionRow): PolicyDecisionView {
  return {
    id: row.id,
    correlationId: row.correlationId,
    subjectKind: row.subjectKind,
    subjectId: row.subjectId,
    subjectLabel: row.subjectLabel,
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    resourceSensitivity: row.resourceSensitivity,
    action: row.action,
    verdict: row.verdict,
    riskScore: row.riskScore,
    matchedRuleId: row.matchedRuleId,
    facts: asRecord(row.facts),
    explanation: asRecord(row.explanation),
    createdAt: row.createdAt.toISOString(),
  };
}

export async function listPolicyRules(
  organizationId: string,
  query: PolicyRuleListQuery,
): Promise<{ rules: PolicyRuleView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.PolicyRuleWhereInput = {
    organizationId,
    ...(query.effect ? { effect: query.effect } : {}),
    ...(query.enabled !== undefined ? { enabled: query.enabled } : {}),
    ...(query.q
      ? {
          OR: [
            { name: { contains: query.q, mode: 'insensitive' } },
            { description: { contains: query.q, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.policyRule.count({ where }),
    prisma.policyRule.findMany({
      where,
      select: RULE_SELECT,
      orderBy: [{ priority: 'asc' }, { name: 'asc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  return {
    rules: rows.map(toRuleView),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getPolicyRule(
  organizationId: string,
  ruleId: string,
): Promise<PolicyRuleView> {
  const row = await prisma.policyRule.findFirst({
    where: { id: ruleId, organizationId },
    select: RULE_SELECT,
  });
  if (!row) throw notFound('Policy rule not found in this organization.');
  return toRuleView(row);
}

export async function createPolicyRule(
  ctx: TenantContext,
  input: CreatePolicyRuleInput,
): Promise<PolicyRuleView> {
  const organizationId = ctx.organization.id;
  try {
    const row = await prisma.$transaction(async (tx) => {
      const created = await tx.policyRule.create({
        data: {
          organizationId,
          name: input.name,
          description: input.description ?? null,
          priority: input.priority,
          effect: input.effect,
          enabled: input.enabled,
          conditions: input.conditions as Prisma.InputJsonValue,
          createdById: ctx.user.id,
        },
        select: RULE_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.POLICY_RULE_CREATED,
        outcome: 'SUCCESS',
        targetType: 'policy_rule',
        targetId: created.id,
        summary: `Created ${created.effect} policy rule "${created.name}" at priority ${created.priority}`,
        metadata: { effect: created.effect, enabled: created.enabled, priority: created.priority },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return created;
    });
    return toRuleView(row);
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict(`A policy rule named "${input.name}" already exists.`);
    }
    throw error;
  }
}

export async function updatePolicyRule(
  ctx: TenantContext,
  ruleId: string,
  input: UpdatePolicyRuleInput,
): Promise<PolicyRuleView> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.policyRule.findFirst({
    where: { id: ruleId, organizationId },
    select: { id: true, name: true, effect: true, enabled: true },
  });
  if (!existing) throw notFound('Policy rule not found in this organization.');

  try {
    const row = await prisma.$transaction(async (tx) => {
      const updated = await tx.policyRule.update({
        where: { id: ruleId },
        data: {
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.description !== undefined ? { description: input.description } : {}),
          ...(input.priority !== undefined ? { priority: input.priority } : {}),
          ...(input.effect !== undefined ? { effect: input.effect } : {}),
          ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
          ...(input.conditions !== undefined
            ? { conditions: input.conditions as Prisma.InputJsonValue }
            : {}),
        },
        select: RULE_SELECT,
      });

      await appendAuditEvent(tx, {
        organizationId,
        actorType: 'USER',
        actorId: ctx.user.id,
        action: AuditActions.POLICY_RULE_UPDATED,
        outcome: 'SUCCESS',
        targetType: 'policy_rule',
        targetId: ruleId,
        summary: `Updated policy rule "${updated.name}"`,
        metadata: {
          fields: Object.keys(input).filter(
            (key) => input[key as keyof UpdatePolicyRuleInput] !== undefined,
          ),
          effectChanged: input.effect !== undefined && input.effect !== existing.effect,
          enabledChanged: input.enabled !== undefined && input.enabled !== existing.enabled,
        },
        ipAddress: ctx.meta.ipAddress,
        userAgent: ctx.meta.userAgent,
        requestId: ctx.meta.requestId,
      });

      return updated;
    });
    return toRuleView(row);
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw conflict('Another policy rule already uses that name.');
    }
    throw error;
  }
}

export async function deletePolicyRule(ctx: TenantContext, ruleId: string): Promise<void> {
  const organizationId = ctx.organization.id;
  const existing = await prisma.policyRule.findFirst({
    where: { id: ruleId, organizationId },
    select: { id: true, name: true, effect: true, priority: true },
  });
  if (!existing) throw notFound('Policy rule not found in this organization.');

  await prisma.$transaction(async (tx) => {
    await tx.policyRule.delete({ where: { id: ruleId } });
    await appendAuditEvent(tx, {
      organizationId,
      actorType: 'USER',
      actorId: ctx.user.id,
      action: AuditActions.POLICY_RULE_DELETED,
      outcome: 'SUCCESS',
      targetType: 'policy_rule',
      targetId: ruleId,
      summary: `Deleted policy rule "${existing.name}"`,
      metadata: { effect: existing.effect, priority: existing.priority },
      ipAddress: ctx.meta.ipAddress,
      userAgent: ctx.meta.userAgent,
      requestId: ctx.meta.requestId,
    });
  });
}

/**
 * Serializes a fact bundle for storage. Dates become ISO strings and only
 * primitives survive, so the stored facts are exactly what the engine read.
 */
function serializeFacts(facts: PolicyFactBundle): Prisma.InputJsonValue {
  return {
    subject: {
      kind: facts.subject.kind,
      id: facts.subject.id,
      label: facts.subject.label,
      role: facts.subject.role,
      attributes: { ...facts.subject.attributes },
    },
    device:
      facts.device === null
        ? null
        : {
            id: facts.device.id,
            managed: facts.device.managed,
            attestationVerified: facts.device.attestationVerified,
            trustState: facts.device.trustState,
            postureFresh: facts.device.postureFresh,
            passedChecks: [...facts.device.passedChecks],
            failingChecks: [...facts.device.failingChecks],
            unknownChecks: [...facts.device.unknownChecks],
          },
    network: {
      zone: facts.network.zone,
      connectorStatus: facts.network.connectorStatus,
      connectorFailMode: facts.network.connectorFailMode,
    },
    resource: {
      type: facts.resource.type,
      id: facts.resource.id,
      sensitivity: facts.resource.sensitivity,
    },
    action: facts.action,
    request: {
      at: facts.request.at.toISOString(),
      mfaSatisfied: facts.request.mfaSatisfied,
      approvalState: facts.request.approvalState,
      correlationId: facts.request.correlationId,
      sourceIp: facts.request.sourceIp,
    },
  };
}

function serializeExplanation(outcome: PolicyOutcome): Prisma.InputJsonValue {
  return {
    summary: outcome.explanation.summary,
    defaulted: outcome.explanation.defaulted,
    reason: outcome.reason,
    obligations: [...outcome.obligations],
    steps: outcome.explanation.steps.map((step) => ({
      ruleId: step.ruleId,
      ruleName: step.ruleName,
      priority: step.priority,
      effect: step.effect,
      matched: step.matched,
      failedConditions: [...step.failedConditions],
    })),
    riskFactors: outcome.riskFactors.map((factor) => ({
      code: factor.code,
      weight: factor.weight,
      detail: factor.detail,
    })),
    stepUpAlreadySatisfied: [...outcome.explanation.stepUpAlreadySatisfied],
    ...(outcome.explanation.invalidRule !== undefined
      ? { invalidRule: outcome.explanation.invalidRule }
      : {}),
  };
}

export interface EvaluatedDecision {
  decision: PolicyDecisionView;
  outcome: PolicyOutcome;
}

/**
 * Evaluates one request and records the verdict with the facts behind it.
 * `at` is captured once so the risk window and the stored timestamp agree.
 */
export async function evaluateDecision(input: {
  organizationId: string;
  request: EvaluationRequestInput;
  at?: Date;
  connectorId?: string | null;
  /** Pre-resolved when the caller already needed the same facts (admission). */
  network?: NetworkFacts;
}): Promise<EvaluatedDecision> {
  const at = input.at ?? new Date();
  const organizationId = input.organizationId;
  const correlationId = input.request.correlationId ?? randomUUID();
  const sourceAddress = input.request.sourceAddress ?? null;

  const [subject, device, rules, network] = await Promise.all([
    resolveSubject(prisma, organizationId, input.request.subject.kind, input.request.subject.id),
    input.request.deviceId
      ? resolveDeviceFacts(prisma, organizationId, input.request.deviceId, at)
      : Promise.resolve(null),
    loadPolicyRules(prisma, organizationId),
    input.network ??
      resolveNetworkFacts(prisma, organizationId, sourceAddress, input.connectorId ?? null),
  ]);

  const requestFacts: PolicyRequestFacts = {
    at,
    mfaSatisfied: input.request.mfaSatisfied,
    approvalState: input.request.approvalState,
    correlationId,
    sourceIp: sourceAddress,
  };
  const resource: PolicyResourceFacts = {
    type: input.request.resource.type,
    id: input.request.resource.id ?? null,
    sensitivity: input.request.resource.sensitivity,
  };

  const facts: PolicyFactBundle = {
    subject,
    device,
    network: {
      zone: network.zone,
      connectorStatus: network.connectorStatus,
      connectorFailMode: network.connectorFailMode,
    },
    resource,
    action: input.request.action,
    request: requestFacts,
  };

  const outcome = evaluatePolicy({ facts, rules });

  const row = await prisma.policyDecision.create({
    data: {
      organizationId,
      correlationId,
      subjectKind: subject.kind,
      subjectId: subject.id,
      subjectLabel: subject.label,
      resourceType: resource.type,
      resourceId: resource.id,
      resourceSensitivity: resource.sensitivity,
      action: input.request.action,
      verdict: outcome.verdict,
      riskScore: outcome.riskScore,
      matchedRuleId: outcome.matchedRuleId,
      requestContext: {
        mfaSatisfied: requestFacts.mfaSatisfied,
        approvalState: requestFacts.approvalState,
        sourceIp: requestFacts.sourceIp,
      },
      facts: serializeFacts(facts),
      explanation: serializeExplanation(outcome),
    },
    select: DECISION_SELECT,
  });

  return { decision: toDecisionView(row), outcome };
}

export async function evaluateRequest(
  organizationId: string,
  request: EvaluationRequestInput,
): Promise<EvaluatedDecision> {
  return evaluateDecision({ organizationId, request });
}

export async function listPolicyDecisions(
  organizationId: string,
  query: PolicyDecisionListQuery,
): Promise<{ decisions: PolicyDecisionView[]; page: ReturnType<typeof paginationMeta> }> {
  const where: Prisma.PolicyDecisionWhereInput = {
    organizationId,
    ...(query.verdict ? { verdict: query.verdict } : {}),
    ...(query.subjectKind ? { subjectKind: query.subjectKind } : {}),
    ...(query.subjectId ? { subjectId: query.subjectId } : {}),
    ...(query.q
      ? {
          OR: [
            { subjectLabel: { contains: query.q, mode: 'insensitive' } },
            { action: { contains: query.q, mode: 'insensitive' } },
            { resourceType: { contains: query.q, mode: 'insensitive' } },
            { correlationId: { contains: query.q, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [total, rows] = await Promise.all([
    prisma.policyDecision.count({ where }),
    prisma.policyDecision.findMany({
      where,
      select: DECISION_SELECT,
      orderBy: { createdAt: 'desc' },
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
    }),
  ]);

  return {
    decisions: rows.map(toDecisionView),
    page: paginationMeta(query.page, query.pageSize, total),
  };
}

export async function getPolicyDecision(
  organizationId: string,
  decisionId: string,
): Promise<PolicyDecisionView> {
  const row = await prisma.policyDecision.findFirst({
    where: { id: decisionId, organizationId },
    select: DECISION_SELECT,
  });
  if (!row) throw notFound('Policy decision not found in this organization.');
  return toDecisionView(row);
}

export interface PolicyOverview {
  rules: { total: number; enabled: number };
  decisions24h: {
    total: number;
    allowed: number;
    denied: number;
    stepUp: number;
    quarantine: number;
  };
  lastDecisionAt: string | null;
}

export async function getPolicyOverview(organizationId: string): Promise<PolicyOverview> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [totalRules, enabledRules, grouped, last] = await Promise.all([
    prisma.policyRule.count({ where: { organizationId } }),
    prisma.policyRule.count({ where: { organizationId, enabled: true } }),
    prisma.policyDecision.groupBy({
      by: ['verdict'],
      where: { organizationId, createdAt: { gte: since } },
      _count: { _all: true },
    }),
    prisma.policyDecision.findFirst({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
      select: { createdAt: true },
    }),
  ]);

  const counts = new Map(grouped.map((entry) => [entry.verdict, entry._count._all]));
  const allowed = counts.get('ALLOW') ?? 0;
  const denied = counts.get('DENY') ?? 0;
  const stepUp = counts.get('STEP_UP') ?? 0;
  const quarantine = counts.get('QUARANTINE') ?? 0;

  return {
    rules: { total: totalRules, enabled: enabledRules },
    decisions24h: {
      total: allowed + denied + stepUp + quarantine,
      allowed,
      denied,
      stepUp,
      quarantine,
    },
    lastDecisionAt: isoOrNull(last?.createdAt),
  };
}
