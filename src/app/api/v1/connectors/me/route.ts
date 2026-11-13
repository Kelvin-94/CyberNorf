import { withConnectorApi } from '@/server/api/connector';
import { jsonResponse } from '@/server/api/handler';

export const dynamic = 'force-dynamic';

/**
 * Credential self-check. A connector calls this after enrolment so a mistyped or
 * revoked token fails loudly instead of at the first flow ingest.
 */
export const GET = withConnectorApi(async ({ meta, connector }) => {
  return jsonResponse(
    {
      connector: {
        id: connector.id,
        name: connector.name,
        kind: connector.kind,
        status: connector.status,
        failMode: connector.failMode,
        capabilities: connector.capabilities,
      },
    },
    meta,
  );
});
