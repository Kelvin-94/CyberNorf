import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { rotateConnectorToken } from '@/server/services/network';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; connectorId: string };

/**
 * Rotation invalidates the previous token immediately; the new plaintext is
 * returned once and only its hash is stored.
 */
export const POST = withTenantApi<Params>('network.manage', {}, async ({ meta, ctx, params }) => {
  const result = await rotateConnectorToken(ctx, params.connectorId);
  return jsonResponse(result, meta);
});
