import { z } from 'zod';
import {
  API_KEY_DEFAULT_TTL_DAYS,
  API_KEY_MAX_TTL_DAYS,
  API_KEY_MIN_TTL_DAYS,
} from '@/server/domain/api-keys';
import { cuidLikeSchema } from './common';

/**
 * A key name is what the owner sees in the console later, so it is a short
 * label ("Nightly export script"), not a comment field.
 */
export const apiKeyCreateSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(3, 'Give the key a name of at least 3 characters.')
      .max(60, 'Key name must be 60 characters or fewer.'),
    organizationId: cuidLikeSchema,
    expiresInDays: z
      .number()
      .int('Expiry must be a whole number of days.')
      .min(API_KEY_MIN_TTL_DAYS, `Choose at least ${API_KEY_MIN_TTL_DAYS} days.`)
      .max(API_KEY_MAX_TTL_DAYS, `Choose at most ${API_KEY_MAX_TTL_DAYS} days.`)
      .default(API_KEY_DEFAULT_TTL_DAYS),
  })
  .strict();

export type ApiKeyCreateInput = z.infer<typeof apiKeyCreateSchema>;

export const apiKeyIdParamSchema = z.object({ keyId: cuidLikeSchema });
