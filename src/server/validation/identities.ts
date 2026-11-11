import { z } from 'zod';
import {
  CREDENTIAL_TTL_DEFAULT_DAYS,
  CREDENTIAL_TTL_MAX_DAYS,
  CREDENTIAL_TTL_MIN_DAYS,
  IDENTITY_CREDENTIAL_SCOPES,
  IDENTITY_TYPES,
  typeMatchesKind,
} from '@/server/domain/identity';
import {
  cuidLikeSchema,
  isoDateTimeSchema,
  optionalDescription,
  optionalShortText,
  paginationSchema,
  searchSchema,
  sortDirectionSchema,
} from './common';

export const identityKindSchema = z.enum(['HUMAN', 'MACHINE']);
export const identityTypeSchema = z.enum(IDENTITY_TYPES);
export const identityStatusSchema = z.enum([
  'PENDING_APPROVAL',
  'ACTIVE',
  'SUSPENDED',
  'DEPROVISIONED',
]);
export const identityCriticalitySchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export const identitySourceSchema = z.enum(['MANUAL', 'IMPORT']);
export const identityEventTypeSchema = z.enum([
  'CREATED',
  'UPDATED',
  'OWNER_ASSIGNED',
  'SUBMITTED_FOR_APPROVAL',
  'APPROVED',
  'SUSPENDED',
  'REACTIVATED',
  'DEPROVISIONED',
  'CREDENTIAL_ISSUED',
  'CREDENTIAL_REVOKED',
  'ACCESS_REVOKED',
]);
export const identityCredentialScopeSchema = z.enum(IDENTITY_CREDENTIAL_SCOPES);

const displayNameSchema = z
  .string()
  .trim()
  .min(1, 'A display name is required.')
  .max(120, 'Display name must be 120 characters or fewer.');

/**
 * Identifiers are emails, service-account names or workload identifiers. They
 * are canonicalized by the service; whitespace is rejected here so an operator
 * cannot hide two distinct values behind trimming.
 */
const identifierSchema = z
  .string()
  .trim()
  .min(2, 'Identifier must be at least 2 characters.')
  .max(200, 'Identifier must be 200 characters or fewer.')
  .regex(/^\S+$/, 'Identifier cannot contain whitespace.')
  .refine(
    (value) =>
      [...value].every((character) => {
        const code = character.codePointAt(0) ?? 0;
        return code > 0x1f && code !== 0x7f;
      }),
    'Identifier contains control characters.',
  );

const ttlSchema = z.coerce.number().int().min(CREDENTIAL_TTL_MIN_DAYS).max(CREDENTIAL_TTL_MAX_DAYS);

export const createIdentitySchema = z
  .object({
    kind: identityKindSchema,
    type: identityTypeSchema,
    displayName: displayNameSchema,
    identifier: identifierSchema,
    description: optionalDescription(2000),
    department: optionalShortText(120),
    criticality: identityCriticalitySchema.default('MEDIUM'),
    source: identitySourceSchema.default('MANUAL'),
    ownerUserId: cuidLikeSchema.nullable().optional(),
    linkedUserId: cuidLikeSchema.nullable().optional(),
    credentialTtlDays: ttlSchema.default(CREDENTIAL_TTL_DEFAULT_DAYS),
    approvedScopes: z.array(identityCredentialScopeSchema).max(1).optional(),
  })
  .superRefine((value, ctx) => {
    if (!typeMatchesKind(value.kind, value.type)) {
      ctx.addIssue({
        code: 'custom',
        path: ['type'],
        message:
          value.kind === 'HUMAN'
            ? 'A human identity must use the USER type.'
            : 'A machine identity cannot use the USER type.',
      });
    }
    if (value.kind === 'MACHINE' && !value.ownerUserId) {
      ctx.addIssue({
        code: 'custom',
        path: ['ownerUserId'],
        message: 'A non-human identity must have an accountable owner.',
      });
    }
    if (value.kind === 'MACHINE' && value.linkedUserId) {
      ctx.addIssue({
        code: 'custom',
        path: ['linkedUserId'],
        message: 'A machine identity cannot be linked to a console account.',
      });
    }
    if (value.kind === 'HUMAN' && value.approvedScopes !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['approvedScopes'],
        message: 'Only non-human identities can be granted credential scopes.',
      });
    }
  });

export type CreateIdentityInput = z.infer<typeof createIdentitySchema>;

export const updateIdentitySchema = z
  .object({
    displayName: displayNameSchema.optional(),
    description: optionalDescription(2000),
    department: optionalShortText(120),
    criticality: identityCriticalitySchema.optional(),
    ownerUserId: cuidLikeSchema.nullable().optional(),
    linkedUserId: cuidLikeSchema.nullable().optional(),
    credentialTtlDays: ttlSchema.optional(),
    approvedScopes: z.array(identityCredentialScopeSchema).max(1).optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'Provide at least one field to update.',
  });

export type UpdateIdentityInput = z.infer<typeof updateIdentitySchema>;

export const identityLifecycleSchema = z.object({
  action: z.enum(['APPROVE', 'SUSPEND', 'REACTIVATE', 'DEPROVISION']),
  note: optionalShortText(500),
});

export type IdentityLifecycleInput = z.infer<typeof identityLifecycleSchema>;

export const issueIdentityCredentialSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, 'A credential name is required.')
    .max(80, 'Credential name must be 80 characters or fewer.'),
  ttlDays: ttlSchema.optional(),
  scopes: z
    .array(identityCredentialScopeSchema)
    .min(1, 'At least one scope is required.')
    .max(1, 'Only one scope is available in this release.')
    .default([...IDENTITY_CREDENTIAL_SCOPES]),
});

export type IssueIdentityCredentialInput = z.infer<typeof issueIdentityCredentialSchema>;

export const identityListQuerySchema = paginationSchema.extend({
  kind: identityKindSchema.optional(),
  type: identityTypeSchema.optional(),
  status: identityStatusSchema.optional(),
  search: searchSchema,
  sort: z
    .enum(['displayName', 'createdAt', 'lastSeenAt', 'criticality', 'status'])
    .default('createdAt'),
  direction: sortDirectionSchema,
});

export type IdentityListQuery = z.infer<typeof identityListQuerySchema>;

export const accessReviewDecisionSchema = z.enum(['RETAIN', 'REVOKE']);

export const createAccessReviewSchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(1, 'A review title is required.')
      .max(120, 'Title must be 120 characters or fewer.'),
    description: optionalDescription(2000),
    dueAt: isoDateTimeSchema,
  })
  .superRefine((value, ctx) => {
    const now = Date.now();
    const due = value.dueAt.getTime();
    if (due <= now) {
      ctx.addIssue({
        code: 'custom',
        path: ['dueAt'],
        message: 'The due date must be in the future.',
      });
    }
    if (due > now + 180 * 24 * 60 * 60 * 1000) {
      ctx.addIssue({
        code: 'custom',
        path: ['dueAt'],
        message: 'The due date cannot be more than 180 days away.',
      });
    }
  });

export type CreateAccessReviewInput = z.infer<typeof createAccessReviewSchema>;

export const decideAccessReviewItemSchema = z.object({
  decision: accessReviewDecisionSchema,
  note: optionalShortText(500),
});

export type DecideAccessReviewItemInput = z.infer<typeof decideAccessReviewItemSchema>;

export const accessReviewListQuerySchema = paginationSchema.extend({
  status: z.enum(['ACTIVE', 'COMPLETED', 'CANCELLED']).optional(),
  search: searchSchema,
});

export type AccessReviewListQuery = z.infer<typeof accessReviewListQuerySchema>;
