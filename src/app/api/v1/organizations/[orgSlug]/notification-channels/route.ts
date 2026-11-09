import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import {
  createNotificationChannel,
  getNotificationSettings,
} from '@/server/services/notifications';
import { createNotificationChannelSchema } from '@/server/validation/notifications';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Alert destinations plus the recent delivery log. Analysts need to read where
 * alerts go and whether they arrived; adding a destination that receives
 * organization telemetry is an administrative change.
 */
export const GET = withTenantApi<Params>('notification.read', {}, async ({ meta, ctx }) => {
  const settings = await getNotificationSettings(ctx);
  return jsonResponse(settings, meta);
});

export const POST = withTenantApi<Params>(
  'notification.manage',
  { rateLimit: { limit: 20, windowSeconds: 60 } },
  async ({ request, meta, ctx }) => {
    const input = createNotificationChannelSchema.parse(await readJsonBody(request));
    const result = await createNotificationChannel(ctx, input);
    return jsonResponse(result, meta, 201);
  },
);
