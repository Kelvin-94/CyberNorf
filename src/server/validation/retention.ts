import { z } from 'zod';
import { RETENTION_POLICY_BOUNDS } from '@/server/services/retention';

const daysSchema = z
  .number()
  .int('Retention windows must be whole days.')
  .min(
    RETENTION_POLICY_BOUNDS.minDays,
    `Retention cannot be shorter than ${RETENTION_POLICY_BOUNDS.minDays} days.`,
  )
  .max(
    RETENTION_POLICY_BOUNDS.maxDays,
    `Retention cannot be longer than ${RETENTION_POLICY_BOUNDS.maxDays} days.`,
  );

export const retentionPolicySchema = z.object({
  agentRunDays: daysSchema,
  notificationEventDays: daysSchema,
  softwareItemDays: daysSchema,
  executionJobDays: daysSchema,
});

/**
 * Preview accepts a complete draft policy so an operator can see what a change
 * would delete before saving it. Every field is optional: an omitted window
 * falls back to the stored policy.
 */
export const retentionPreviewQuerySchema = z.object({
  agentRunDays: z.coerce.number().int().min(1).max(RETENTION_POLICY_BOUNDS.maxDays).optional(),
  notificationEventDays: z.coerce
    .number()
    .int()
    .min(1)
    .max(RETENTION_POLICY_BOUNDS.maxDays)
    .optional(),
  softwareItemDays: z.coerce.number().int().min(1).max(RETENTION_POLICY_BOUNDS.maxDays).optional(),
  executionJobDays: z.coerce.number().int().min(1).max(RETENTION_POLICY_BOUNDS.maxDays).optional(),
});

/**
 * Purge is irreversible, so the request has to carry the literal word. A
 * boolean flag would be set by any client that defaults to `true`; a string
 * cannot be supplied by accident.
 */
export const purgeRetentionSchema = z.object({
  confirm: z.literal('PURGE', {
    message: 'Send confirm: "PURGE" to delete retained history.',
  }),
});
