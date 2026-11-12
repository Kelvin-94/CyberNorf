import { z } from 'zod';
import {
  EXECUTION_CAPABILITIES,
  JOB_LIMIT_CEILINGS,
  SCOPE_ENTRY_KINDS,
  SCOPE_TARGET_TYPES,
} from '@/server/domain/execution';
import {
  isoDateTimeSchema,
  optionalDescription,
  optionalShortText,
  paginationSchema,
  searchSchema,
  sortDirectionSchema,
} from './common';

export const engagementStatusSchema = z.enum(['DRAFT', 'ACTIVE', 'PAUSED', 'CLOSED']);
export const scopeTargetTypeSchema = z.enum(SCOPE_TARGET_TYPES);
export const scopeEntryKindSchema = z.enum(SCOPE_ENTRY_KINDS);
export const executionCapabilitySchema = z.enum(EXECUTION_CAPABILITIES);
export const authorizationDecisionSchema = z.enum(['APPROVED', 'REJECTED']);
export const workerStatusSchema = z.enum(['ACTIVE', 'SUSPENDED', 'RETIRED']);
export const jobReviewDecisionSchema = z.enum(['APPROVED', 'REJECTED']);
export const jobOutcomeSchema = z.enum(['SUCCEEDED', 'FAILED']);

const nameSchema = z
  .string()
  .trim()
  .min(3, 'Name must be at least 3 characters.')
  .max(120, 'Name must be 120 characters or fewer.');

export const createEngagementSchema = z
  .object({
    name: nameSchema,
    description: optionalDescription(2000),
    startsAt: isoDateTimeSchema,
    endsAt: isoDateTimeSchema,
  })
  .refine((value) => value.endsAt.getTime() > value.startsAt.getTime(), {
    message: 'The engagement must end after it starts.',
    path: ['endsAt'],
  });

export const updateEngagementSchema = z
  .object({
    name: nameSchema.optional(),
    description: optionalDescription(2000),
    status: engagementStatusSchema.optional(),
    startsAt: isoDateTimeSchema.optional(),
    endsAt: isoDateTimeSchema.optional(),
  })
  .refine((value) => Object.values(value).some((entry) => entry !== undefined), {
    message: 'Provide at least one field to update.',
  });

export const engagementListQuerySchema = z.object({
  search: searchSchema,
  status: engagementStatusSchema.optional(),
  page: paginationSchema.shape.page,
  pageSize: paginationSchema.shape.pageSize,
  sort: z.enum(['createdAt', 'endsAt', 'name']).default('createdAt'),
  direction: sortDirectionSchema,
});

export const createScopeEntrySchema = z.object({
  kind: scopeEntryKindSchema,
  targetType: scopeTargetTypeSchema,
  value: z
    .string()
    .trim()
    .min(1, 'A target value is required.')
    .max(2048, 'The target value is too long.'),
  note: optionalShortText(500),
});

export const engagementScopeQuerySchema = z.object({
  kind: scopeEntryKindSchema.optional(),
});

export const requestAuthorizationSchema = z.object({
  expiresAt: isoDateTimeSchema,
  // The external authorization (signed scope, ticket, contract reference) is
  // mandatory: an approval without a reference is an assertion, not a record.
  reference: z
    .string()
    .trim()
    .min(3, 'Record the authorization reference.')
    .max(200, 'The reference must be 200 characters or fewer.'),
  conditions: optionalDescription(2000),
});

export const decideAuthorizationSchema = z.object({
  decision: authorizationDecisionSchema,
  note: optionalShortText(500),
});

export const revokeAuthorizationSchema = z.object({
  reason: z
    .string()
    .trim()
    .min(3, 'A revocation reason is required.')
    .max(500, 'The reason must be 500 characters or fewer.'),
});

export const registerWorkerSchema = z.object({
  name: nameSchema,
  isolated: z.boolean(),
  egressAllowlist: z
    .array(z.string().trim().min(1).max(253))
    .min(1, 'At least one egress destination is required.')
    .max(50, 'At most 50 egress destinations are allowed.'),
  attestationRef: optionalShortText(200),
});

export const updateWorkerSchema = z
  .object({
    status: workerStatusSchema.optional(),
    isolated: z.boolean().optional(),
    egressAllowlist: z.array(z.string().trim().min(1).max(253)).min(1).max(50).optional(),
    attestationRef: optionalShortText(200),
    heartbeat: z.boolean().optional(),
  })
  .refine((value) => Object.values(value).some((entry) => entry !== undefined), {
    message: 'Provide at least one field to update.',
  });

export const workerListQuerySchema = z.object({
  status: workerStatusSchema.optional(),
  page: paginationSchema.shape.page,
  pageSize: paginationSchema.shape.pageSize,
});

const positiveLimit = (ceiling: number) =>
  z.coerce.number().int().min(1).max(ceiling, `Must be ${ceiling} or fewer.`);

export const jobLimitsSchema = z.object({
  maxDurationSeconds: positiveLimit(JOB_LIMIT_CEILINGS.maxDurationSeconds).optional(),
  maxRequests: positiveLimit(JOB_LIMIT_CEILINGS.maxRequests).optional(),
  maxBytes: positiveLimit(JOB_LIMIT_CEILINGS.maxBytes).optional(),
  maxConcurrency: positiveLimit(JOB_LIMIT_CEILINGS.maxConcurrency).optional(),
});

export const createExecutionJobSchema = z.object({
  capability: executionCapabilitySchema,
  targetType: scopeTargetTypeSchema,
  targetValue: z.string().trim().min(1).max(2048),
  workerId: z.string().trim().min(1).max(64).optional(),
  limits: jobLimitsSchema.optional(),
});

export const jobListQuerySchema = z.object({
  status: z
    .enum(['PENDING_REVIEW', 'QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'DENIED'])
    .optional(),
  page: paginationSchema.shape.page,
  pageSize: paginationSchema.shape.pageSize,
});

export const reviewExecutionJobSchema = z.object({
  decision: jobReviewDecisionSchema,
  note: optionalShortText(1000),
});

export const cancelExecutionJobSchema = z.object({
  reason: z
    .string()
    .trim()
    .min(3, 'A cancellation reason is required.')
    .max(500, 'The reason must be 500 characters or fewer.'),
});

export const completeExecutionJobSchema = z.object({
  outcome: jobOutcomeSchema,
  summary: optionalShortText(1000),
});
