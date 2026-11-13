import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { dispatchEnforcement } from '@/server/services/enforcement';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; actionId: string };

/**
 * Dispatch hands the command to the connector bound to the action. It is the
 * last operator-driven step; acknowledgement and verification are reported by
 * the connector over its own token-authenticated channel.
 */
export const POST = withTenantApi<Params>(
  'enforcement.manage',
  {},
  async ({ meta, ctx, params }) => {
    const action = await dispatchEnforcement(ctx, params.actionId);
    return jsonResponse({ action }, meta);
  },
);
