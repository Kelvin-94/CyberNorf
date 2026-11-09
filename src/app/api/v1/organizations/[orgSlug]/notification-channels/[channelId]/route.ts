import { emptyResponse, withTenantApi } from '@/server/api/handler';
import { deleteNotificationChannel } from '@/server/services/notifications';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; channelId: string };

/**
 * Removing a destination also removes its queued and historical deliveries: the
 * rows exist to tell an operator what was sent where, and that record has no
 * meaning once the endpoint is gone.
 */
export const DELETE = withTenantApi<Params>(
  'notification.manage',
  {},
  async ({ meta, ctx, params }) => {
    await deleteNotificationChannel(ctx, params.channelId);
    return emptyResponse(meta);
  },
);
