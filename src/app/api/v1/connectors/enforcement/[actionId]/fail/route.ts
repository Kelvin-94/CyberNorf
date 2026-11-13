import { withConnectorApi } from '@/server/api/connector';
import { jsonResponse } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import {
  assertConnectorActor,
  assertConnectorBound,
  failEnforcement,
} from '@/server/services/enforcement';
import { failEnforcementSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { actionId: string };

/**
 * A connector that could not carry out the command says so with a reason. The
 * action becomes FAILED rather than remaining armed, and the reason is what an
 * operator sees when they ask why a containment did not happen.
 */
export const POST = withConnectorApi<Params>(async ({ request, meta, connector, params }) => {
  const input = failEnforcementSchema.parse(await readJsonBody(request));

  const actor = {
    type: 'SYSTEM' as const,
    id: connector.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
  };
  assertConnectorActor(actor);

  await assertConnectorBound(connector.organizationId, params.actionId, connector.id);
  const action = await failEnforcement(
    actor,
    connector.organizationId,
    params.actionId,
    input.reason,
  );

  return jsonResponse({ action }, meta);
});
