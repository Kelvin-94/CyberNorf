import { withConnectorApi } from '@/server/api/connector';
import { jsonResponse } from '@/server/api/handler';
import {
  assertConnectorActor,
  assertConnectorBound,
  verifyEnforcement,
} from '@/server/services/enforcement';

export const dynamic = 'force-dynamic';

type Params = { actionId: string };

/**
 * Verification is a separate claim from acknowledgement: the connector reports
 * that it observed the effect (the session is gone, the port is closed), not
 * merely that the command was applied.
 */
export const POST = withConnectorApi<Params>(async ({ meta, connector, params }) => {
  const actor = {
    type: 'SYSTEM' as const,
    id: connector.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
  };
  assertConnectorActor(actor);

  await assertConnectorBound(connector.organizationId, params.actionId, connector.id);
  const action = await verifyEnforcement(actor, connector.organizationId, params.actionId);

  return jsonResponse({ action }, meta);
});
