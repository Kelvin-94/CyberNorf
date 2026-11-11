import { z } from 'zod';
import { isoDateTimeSchema } from './common';

/**
 * Validation for indicators of compromise.
 *
 * The value itself is validated in the domain layer, not here: normalisation
 * depends on the declared type (an MD5 and a domain are both "a string"), and
 * duplicating those rules in Zod would give two definitions of a valid indicator
 * that can drift apart. This layer checks shape and bounds; the domain layer
 * decides whether the value is real.
 */

export const indicatorTypeSchema = z.enum([
  'IPV4',
  'IPV6',
  'DOMAIN',
  'URL',
  'SHA256',
  'MD5',
  'EMAIL',
]);

export const indicatorStatusSchema = z.enum(['ACTIVE', 'EXPIRED', 'FALSE_POSITIVE']);

export const indicatorSourceKindSchema = z.enum(['MANUAL', 'IMPORT']);

export const indicatorRelationSchema = z.enum(['OBSERVED', 'REFERENCED']);

/** A source is mandatory: an indicator with no provenance cannot be defended. */
const sourceNameSchema = z
  .string()
  .trim()
  .min(1, 'Name the feed, report or analyst that supplied this indicator.')
  .max(200, 'Source name is too long.');

const sourceUrlSchema = z
  .string()
  .trim()
  .max(2048)
  .refine((value) => {
    try {
      const url = new URL(value);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
      return false;
    }
  }, 'Source URL must be an absolute http or https URL.');

const confidenceSchema = z
  .number()
  .int('Confidence is a whole percentage.')
  .min(0, 'Confidence cannot be below 0.')
  .max(100, 'Confidence cannot be above 100.');

export const createIndicatorSchema = z
  .object({
    // Optional: when absent the type is inferred from the value.
    type: indicatorTypeSchema.optional(),
    value: z.string().trim().min(1, 'An indicator value is required.').max(2048),
    confidence: confidenceSchema.optional(),
    sourceName: sourceNameSchema,
    sourceUrl: sourceUrlSchema.nullable().optional(),
    sourceRef: z.string().trim().max(200).nullable().optional(),
    firstSeenAt: isoDateTimeSchema.optional(),
    lastSeenAt: isoDateTimeSchema.optional(),
    expiresAt: isoDateTimeSchema.nullable().optional(),
    note: z.string().trim().max(2000).nullable().optional(),
  })
  .strict();

export const updateIndicatorSchema = z
  .object({
    status: indicatorStatusSchema.optional(),
    confidence: confidenceSchema.optional(),
    expiresAt: isoDateTimeSchema.nullable().optional(),
    note: z.string().trim().max(2000).nullable().optional(),
    lastSeenAt: isoDateTimeSchema.optional(),
  })
  .strict()
  .refine(
    (value) =>
      value.status !== undefined ||
      value.confidence !== undefined ||
      value.expiresAt !== undefined ||
      value.note !== undefined ||
      value.lastSeenAt !== undefined,
    { message: 'Provide at least one field to update.' },
  );

/**
 * Import cap: one request may carry 5,000 indicators. Higher would mean a body
 * large enough to be a memory problem and a transaction long enough to hold a
 * quota lock for seconds, which every other writer for that tenant then waits on.
 */
export const IMPORT_MAX_INDICATORS = 5_000;

export const importIndicatorsSchema = z
  .object({
    sourceName: sourceNameSchema,
    sourceKind: indicatorSourceKindSchema.optional(),
    sourceUrl: sourceUrlSchema.nullable().optional(),
    indicators: z
      .array(
        z
          .object({
            type: indicatorTypeSchema.optional(),
            value: z.string().trim().min(1).max(2048),
          })
          .strict(),
      )
      .min(1, 'Supply at least one indicator.')
      .max(
        IMPORT_MAX_INDICATORS,
        `A single import is limited to ${IMPORT_MAX_INDICATORS} indicators.`,
      ),
  })
  .strict();

export const linkIndicatorSchema = z
  .object({
    findingId: z.string().trim().min(1).optional(),
    incidentId: z.string().trim().min(1).optional(),
    relation: indicatorRelationSchema.optional(),
    note: z.string().trim().max(1000).nullable().optional(),
  })
  .strict()
  .refine((value) => Boolean(value.findingId) !== Boolean(value.incidentId), {
    message: 'Supply exactly one of findingId or incidentId.',
  });

export const indicatorQuerySchema = z
  .object({
    search: z.string().trim().max(200).optional(),
    type: indicatorTypeSchema.optional(),
    status: indicatorStatusSchema.optional(),
    expired: z.enum(['true', 'false']).optional(),
    page: z.coerce.number().int().min(1).max(10_000).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
    sort: z.enum(['lastSeenAt', 'firstSeenAt', 'createdAt', 'confidence']).default('lastSeenAt'),
    direction: z.enum(['asc', 'desc']).default('desc'),
  })
  .strict();
