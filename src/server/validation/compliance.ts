import { z } from 'zod';
import {
  cuidLikeSchema,
  isoDateTimeSchema,
  optionalDescription,
  optionalShortText,
} from './common';

export const controlStatusSchema = z.enum([
  'NOT_STARTED',
  'IN_PROGRESS',
  'PARTIAL',
  'IMPLEMENTED',
  'NOT_APPLICABLE',
]);

export const evidenceKindSchema = z.enum(['FINDING', 'INCIDENT', 'ASSET', 'REFERENCE']);

export const adoptFrameworkSchema = z.object({
  frameworkId: cuidLikeSchema,
  targetDate: isoDateTimeSchema.nullable().optional(),
});

/** The framework is addressed by code in the path, so no body is required. */
export const updateFrameworkSchema = z
  .object({
    targetDate: isoDateTimeSchema.nullable().optional(),
  })
  .strict();

/**
 * Attestation update. Every field is optional so a PATCH can move the owner or
 * add a review note without restating the status, but an empty body is
 * rejected: an update that changes nothing should not produce an audit event.
 */
export const updateControlSchema = z
  .object({
    status: controlStatusSchema.optional(),
    ownerId: cuidLikeSchema.nullable().optional(),
    notes: optionalDescription(2000),
    nextReviewAt: isoDateTimeSchema.nullable().optional(),
  })
  .strict()
  .refine(
    (value) =>
      value.status !== undefined ||
      value.ownerId !== undefined ||
      value.notes !== undefined ||
      value.nextReviewAt !== undefined,
    { message: 'Provide at least one field to update.' },
  );

const referenceSchema = z
  .string()
  .trim()
  .min(3, 'Reference must be at least 3 characters.')
  .max(500, 'Reference is too long.')
  .refine(
    (value) => /^(https?:\/\/|ticket:|doc:|ref:)/i.test(value) || value.length >= 5,
    'Use an https:// link or a ticket identifier.',
  );

/**
 * Evidence must point at exactly one target. The refinement mirrors the
 * database CHECK constraint so callers get a 422 with a field-level message
 * instead of a constraint violation.
 */
export const createEvidenceSchema = z
  .object({
    kind: evidenceKindSchema,
    findingId: cuidLikeSchema.optional(),
    incidentId: cuidLikeSchema.optional(),
    assetId: cuidLikeSchema.optional(),
    reference: referenceSchema.optional(),
    note: optionalShortText(500),
  })
  .strict()
  .superRefine((value, ctx) => {
    const targetKey = {
      FINDING: 'findingId',
      INCIDENT: 'incidentId',
      ASSET: 'assetId',
      REFERENCE: 'reference',
    }[value.kind] as 'findingId' | 'incidentId' | 'assetId' | 'reference';

    const provided = (['findingId', 'incidentId', 'assetId', 'reference'] as const).filter(
      (key) => value[key] !== undefined && value[key] !== null,
    );

    if (provided.length === 0) {
      ctx.addIssue({
        code: 'custom',
        path: [targetKey],
        message: `A ${value.kind.toLowerCase()} reference is required.`,
      });
      return;
    }

    const mismatched = provided.filter((key) => key !== targetKey);
    if (mismatched.length > 0) {
      ctx.addIssue({
        code: 'custom',
        path: [mismatched[0] as string],
        message: `Evidence of kind ${value.kind} only accepts ${targetKey}.`,
      });
    }
  });

export const complianceQuerySchema = z.object({
  framework: z
    .string()
    .trim()
    .max(40)
    .optional()
    .transform((value) => (value && value.length > 0 ? value.toUpperCase() : undefined)),
});

export type ControlStatusInput = z.infer<typeof controlStatusSchema>;
export type EvidenceKindInput = z.infer<typeof evidenceKindSchema>;
