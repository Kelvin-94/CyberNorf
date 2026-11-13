import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getConnector, updateConnector } from '@/server/services/network';
import { updateConnectorSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; connectorId: string };

export const GET = withTenantApi<Params>('network.read', {}, async ({ meta, ctx, params }) => {
  const connector = await getConnector(ctx.organization.id, params.connectorId);
  return jsonResponse({ connector }, meta);
});

export const PATCH = withTenantApi<Params>(
  'network.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateConnectorSchema.parse(await readJsonBody(request));
    const connector = await updateConnector(ctx, params.connectorId, input);
    return jsonResponse({ connector }, meta);
  },
);
