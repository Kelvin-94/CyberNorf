import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { createConnector, listConnectors } from '@/server/services/network';
import { parseQuery } from '@/server/validation/common';
import { connectorListQuerySchema, createConnectorSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('network.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, connectorListQuerySchema);
  const result = await listConnectors(ctx.organization.id, query);
  return jsonResponse(result, meta);
});

/**
 * The registration token is returned exactly once, in the create response, so a
 * connector can enrol without the plaintext ever being stored server-side.
 */
export const POST = withTenantApi<Params>('network.manage', {}, async ({ request, meta, ctx }) => {
  const input = createConnectorSchema.parse(await readJsonBody(request));
  const result = await createConnector(ctx, input);
  return jsonResponse(result, meta, 201);
});
