import { emptyResponse, withTenantApi } from '@/server/api/handler';
import { deleteAdvisory } from '@/server/services/software';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; advisoryId: string };

/**
 * Removing an advisory stops future matches. Findings it already raised stay in
 * the console: an operator triages or closes them, and the audit log keeps the
 * record of why they existed.
 */
export const DELETE = withTenantApi<Params>(
  'advisory.manage',
  {},
  async ({ meta, ctx, params }) => {
    await deleteAdvisory(ctx, params.advisoryId);
    return emptyResponse(meta);
  },
);
