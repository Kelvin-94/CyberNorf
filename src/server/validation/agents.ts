import { z } from 'zod';
import { AGENT_SCOPES, AGENT_SOURCES } from '@/server/domain/agents';
import {
  cuidLikeSchema,
  isoDateTimeSchema,
  optionalDescription,
  optionalShortText,
} from './common';
import { MAX_INVENTORY_ITEMS, softwareItemSchema } from './software';

export const agentSourceSchema = z.enum(AGENT_SOURCES);
export const agentScopeSchema = z.enum(AGENT_SCOPES);

/**
 * Agents are addressed by name in conversation and in the console, so the name
 * is constrained to readable characters and unique per organization.
 */
export const agentNameSchema = z
  .string()
  .trim()
  .min(2, 'Agent name must be at least 2 characters.')
  .max(60, 'Agent name must be 60 characters or fewer.')
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9 ._()-]*$/,
    'Use letters, digits, spaces, dots, underscores, hyphens or parentheses.',
  );

export const registerAgentSchema = z
  .object({
    name: agentNameSchema,
    description: optionalDescription(500),
    source: agentSourceSchema,
    scopes: z.array(agentScopeSchema).min(1).max(AGENT_SCOPES.length).optional(),
  })
  .strict();

/** Approval may narrow the scopes requested at registration, never widen them. */
export const approveAgentSchema = z
  .object({
    scopes: z.array(agentScopeSchema).min(1).max(AGENT_SCOPES.length).optional(),
    note: optionalShortText(300),
  })
  .strict();

/** Suspend and resume carry an optional operator note for the audit trail. */
export const agentLifecycleSchema = z
  .object({
    note: optionalShortText(300),
  })
  .strict();

const CHECK_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{1,79}$/i;

/**
 * One monitoring check. The identifier is stable across runs: it is the dedupe
 * key for findings, so an agent must not rename a check between runs.
 */
export const agentCheckSchema = z
  .object({
    id: z
      .string()
      .trim()
      .max(80, 'Check id must be 80 characters or fewer.')
      .regex(CHECK_ID_PATTERN, 'Use letters, digits, dots, underscores or hyphens.'),
    title: z.string().trim().min(3, 'Check title is required.').max(200),
    // The control name reads as the pass condition ("Host firewall state"). A
    // finding needs the faulty state instead ("Host firewall is disabled"), so
    // agents may send it explicitly and the server prefers it when creating a
    // finding. The check id remains the fingerprint, so titles stay cosmetic.
    findingTitle: z.string().trim().min(3).max(200).optional(),
    status: z.enum(['PASS', 'FAIL', 'SKIP']),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).default('MEDIUM'),
    target: optionalShortText(120),
    detail: optionalShortText(1000),
    remediation: optionalShortText(1000),
  })
  .strict();

const MAX_CHECKS_PER_RUN = 200;

/**
 * Run report submitted by an agent. Counts and status are not accepted from the
 * agent: they are derived server-side from `checks`, so a compromised or buggy
 * agent cannot report a clean posture it did not observe.
 */
export const agentRunReportSchema = z
  .object({
    hostname: optionalShortText(120),
    platform: optionalShortText(120),
    startedAt: isoDateTimeSchema,
    finishedAt: isoDateTimeSchema.optional(),
    durationMs: z
      .number()
      .int()
      .min(0)
      .max(24 * 60 * 60 * 1000)
      .optional(),
    checks: z.array(agentCheckSchema).max(MAX_CHECKS_PER_RUN, 'Too many checks in one run.'),
    // Optional software inventory for the host. It is a snapshot of the last
    // run, used for advisory matching rather than for posture scoring.
    inventory: z
      .array(softwareItemSchema)
      .max(MAX_INVENTORY_ITEMS, 'Too many packages in one run.')
      .optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const seen = new Set<string>();
    value.checks.forEach((check, index) => {
      const key = `${check.id}::${check.target ?? ''}`;
      if (seen.has(key)) {
        ctx.addIssue({
          code: 'custom',
          path: ['checks', index, 'id'],
          message: `Duplicate check ${check.id} for the same target in one run.`,
        });
      }
      seen.add(key);
    });

    const packages = new Set<string>();
    value.inventory?.forEach((item, index) => {
      const key = `${item.ecosystem}::${item.name.toLowerCase()}`;
      if (packages.has(key)) {
        ctx.addIssue({
          code: 'custom',
          path: ['inventory', index, 'name'],
          message: `Package ${item.name} is listed twice for ${item.ecosystem} in one run.`,
        });
      }
      packages.add(key);
    });
  });

export const agentIdParamSchema = z.object({ agentId: cuidLikeSchema });

/**
 * Link between a monitoring check and one adopted-framework control. The check
 * id is the same identifier the agent reports, so the mapping survives renames
 * of the human-readable title.
 */
export const createCheckMapSchema = z
  .object({
    checkId: z
      .string()
      .trim()
      .max(80, 'Check id must be 80 characters or fewer.')
      .regex(CHECK_ID_PATTERN, 'Use letters, digits, dots, underscores or hyphens.'),
    organizationControlId: cuidLikeSchema,
  })
  .strict();

/**
 * Operator expectation for reporting cadence, in minutes. Null clears the
 * expectation and turns offline detection off for that agent. The lower bound
 * keeps a badly chosen interval from producing an alert loop.
 */
export const agentHeartbeatSchema = z
  .object({
    expectedIntervalMinutes: z
      .number()
      .int('Use whole minutes.')
      .min(5, 'Check at least every 5 minutes.')
      .max(10080, 'Use an interval of seven days or less.')
      .nullable(),
  })
  .strict();

export type AgentHeartbeatInput = z.infer<typeof agentHeartbeatSchema>;

/** The overview is scoped to one agent's observed checks when an id is given. */
export const checkMapQuerySchema = z.object({ agentId: cuidLikeSchema.optional() });

export type CreateCheckMapInput = z.infer<typeof createCheckMapSchema>;

export type AgentSourceInput = z.infer<typeof agentSourceSchema>;
export type AgentScopeInput = z.infer<typeof agentScopeSchema>;
export type RegisterAgentInput = z.infer<typeof registerAgentSchema>;
export type AgentCheckInput = z.infer<typeof agentCheckSchema>;
export type AgentRunReportInput = z.infer<typeof agentRunReportSchema>;
