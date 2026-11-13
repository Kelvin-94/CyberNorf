import { withConnectorApi } from '@/server/api/connector';
import { jsonResponse } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import {
  acknowledgeEnforcement,
  assertConnectorActor,
  assertConnectorBound,
} from '@/server/services/enforcement';
import { enforcementResultSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { actionId: string };

/**
 * Acknowledgement means the connector received and applied the command. It is
 * refused when the action is not bound to this connector, so one gateway cannot
 * close another gateway's command.
 */
export const POST = withConnectorApi<Params>(async ({ request, meta, connector, params }) => {
  const input = enforcementResultSchema.parse(await readJsonBody(request));

  const actor = {
    type: 'SYSTEM' as const,
    id: connector.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
  };
  assertConnectorActor(actor);

  await assertConnectorBound(connector.organizationId, params.actionId, connector.id);
  const action = await acknowledgeEnforcement(
    actor,
    connector.organizationId,
    params.actionId,
    input.result,
  );

  return jsonResponse({ action }, meta);
});
