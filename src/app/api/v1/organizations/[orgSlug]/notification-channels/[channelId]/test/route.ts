import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { sendTestNotification } from '@/server/services/notifications';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; channelId: string };

/**
 * Delivers one signed test event and reports the outcome. The limits keep the
 * button from being used to make the server emit traffic at a third-party
 * endpoint in a loop.
 */
export const POST = withTenantApi<Params>(
  'notification.manage',
  { rateLimit: { limit: 6, windowSeconds: 60 } },
  async ({ meta, ctx, params }) => {
    const result = await sendTestNotification(ctx, params.channelId);
    return jsonResponse({ delivery: result }, meta);
  },
);
