import { jsonResponse, withTenantApi } from '@/server/api/handler';
import {
  getRetentionPolicy,
  planRetentionPolicy,
  type RetentionPolicy,
} from '@/server/services/retention';
import { parseQuery } from '@/server/validation/common';
import { retentionPreviewQuerySchema } from '@/server/validation/retention';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Read-only preview of what the stored policy would delete right now. It takes
 * optional draft windows so the UI can show the effect of a change before it is
 * saved; nothing here can delete a row.
 */
export const GET = withTenantApi<Params>('retention.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, retentionPreviewQuerySchema);
  const stored = await getRetentionPolicy(ctx.organization.id);

  const draft: RetentionPolicy = {
    agentRunDays: query.agentRunDays ?? stored.policy.agentRunDays,
    notificationEventDays: query.notificationEventDays ?? stored.policy.notificationEventDays,
    softwareItemDays: query.softwareItemDays ?? stored.policy.softwareItemDays,
    executionJobDays: query.executionJobDays ?? stored.policy.executionJobDays,
  };

  const plan = await planRetentionPolicy(ctx.organization.id, { policy: draft });
  return jsonResponse({ preview: plan }, meta);
});
