import { z } from 'zod';

/**
 * A webhook destination and the shared secret used to sign deliveries. The
 * secret is supplied by the operator rather than generated here: their endpoint
 * already needs to know it, and keeping the two in sync avoids a reveal step
 * that would have to survive a page refresh.
 */
export const createNotificationChannelSchema = z
  .object({
    name: z.string().trim().min(2, 'Use at least 2 characters.').max(60),
    url: z.url('Enter an absolute URL, for example https://alerts.example.com/hooks/cybernorf'),
    secret: z
      .string()
      .min(32, 'Use at least 32 characters; shorter secrets are easy to guess.')
      .max(200, 'Use 200 characters or fewer.'),
  })
  .strict();

export type CreateNotificationChannelInput = z.infer<typeof createNotificationChannelSchema>;
