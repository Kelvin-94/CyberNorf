import { z } from 'zod';
import { cuidLikeSchema, isoDateTimeSchema, optionalShortText } from './common';

export const auditQuerySchema = z.object({
  search: optionalShortText(),
  action: z
    .string()
    .trim()
    .max(80)
    .regex(/^[a-z]+(?:[._][a-z_]+)*$/, 'Action filters use the action identifier form.')
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
