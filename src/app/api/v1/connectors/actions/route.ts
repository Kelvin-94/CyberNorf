import { withConnectorApi } from '@/server/api/connector';
import { jsonResponse } from '@/server/api/handler';
import { listConnectorQueue } from '@/server/services/enforcement';

export const dynamic = 'force-dynamic';

/**
 * The connector's poll target. Only actions dispatched to this connector are
 * returned; the queue is ordered oldest first so a command cannot be starved by
 * a steady stream of newer ones.
 */
export const GET = withConnectorApi(async ({ meta, connector }) => {
  const queue = await listConnectorQueue(connector.organizationId, connector.id);
  return jsonResponse(queue, meta);
});
