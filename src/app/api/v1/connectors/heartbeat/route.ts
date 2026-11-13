import { withConnectorApi } from '@/server/api/connector';
import { jsonResponse } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { recordConnectorHeartbeat } from '@/server/services/network';
import { connectorHeartbeatSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

/**
 * Reachability as the connector sees it. Admission reads the stored status, so
 * a connector that stops heartbeating is eventually treated as unreachable and
 * its fail mode decides what happens to new admissions.
 */
export const POST = withConnectorApi(async ({ request, meta, connector }) => {
  const input = connectorHeartbeatSchema.parse(await readJsonBody(request));
  await recordConnectorHeartbeat(connector.id, input.status);
  return jsonResponse({ recorded: true, status: input.status }, meta);
});
