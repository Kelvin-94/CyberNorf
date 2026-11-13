import { withConnectorApi } from '@/server/api/connector';
import { jsonResponse } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { ingestFlows } from '@/server/services/network';
import { ingestFlowsSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

/**
 * Flow and telemetry ingestion. The connector supplies observations only: the
 * addresses, ports and bytes it saw. Segmentation, correlation and detections
 * are derived server-side from those facts.
 */
export const POST = withConnectorApi(async ({ request, meta, connector }) => {
  const input = ingestFlowsSchema.parse(await readJsonBody(request));
  const result = await ingestFlows({
    organizationId: connector.organizationId,
    connectorId: connector.id,
    flows: input.flows,
    actor: {
      type: 'SYSTEM',
      id: connector.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      requestId: meta.requestId,
    },
  });
  return jsonResponse(result, meta, 201);
});
