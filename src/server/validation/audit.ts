import { z } from 'zod';
import { cuidLikeSchema, isoDateTimeSchema, optionalShortText } from './common';

/** Longest action identifier the console accepts as a filter. */
export const AUDIT_ACTION_MAX_LENGTH = 80;

const ACTION_FIRST_SEGMENT = /^[a-z]+$/;
const ACTION_SEGMENT = /^[a-z_]+$/;

/**
 * Action identifiers are lowercase segments separated by `.` or `_`, e.g.
 * `user.login`, `agent.run.succeeded` or `user.login_failed`.
 *
 * The check is a linear scan instead of one regular expression. A single
 * expression such as `^[a-z]+(?:[._][a-z_]+)*$` is ambiguous because `_` is
 * accepted by both the separator-following class and the segment-start class,
 * so an input like `a.` followed by a long run of underscores makes the engine
 * backtrack over every way to split that run (exponential time, request thread
 * stalled). Splitting on a separator and validating each segment keeps the work
 * O(n) for any input.
 *
 * Compared with that expression, an identifier that puts `.` directly before
 * `_` (`a._b`) is now rejected. No emitted action name looks like that, and the
 * stricter rule also keeps separators from doubling up.
 */
export function isAuditAction(value: string): boolean {
  return value
    .split(/[._]/)
    .every((segment, index) =>
      index === 0 ? ACTION_FIRST_SEGMENT.test(segment) : ACTION_SEGMENT.test(segment),
    );
}

export const auditQuerySchema = z.object({
  search: optionalShortText(),
  action: z
    .string()
    .trim()
    .max(AUDIT_ACTION_MAX_LENGTH)
    .refine(isAuditAction, 'Action filters use the action identifier form.')
    .optional(),
  outcome: z.enum(['SUCCESS', 'DENIED', 'FAILURE']).optional(),
  targetType: z
    .string()
    .trim()
    .max(40)
    .regex(/^[a-z_]+$/, 'Target type filters use lowercase identifiers.')
    .optional(),
  actorId: cuidLikeSchema.optional(),
  from: isoDateTimeSchema.optional(),
  to: isoDateTimeSchema.optional(),
  page: z.coerce.number().int().min(1).max(10000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  direction: z.enum(['asc', 'desc']).default('desc'),
});

export type AuditQuery = z.infer<typeof auditQuerySchema>;
