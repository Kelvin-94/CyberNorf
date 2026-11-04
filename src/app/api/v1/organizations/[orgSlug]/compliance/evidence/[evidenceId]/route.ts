import { emptyResponse, withTenantApi } from '@/server/api/handler';
import { deleteEvidence } from '@/server/services/compliance';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; evidenceId: string };

export const DELETE = withTenantApi<Params>(
  'compliance.evidence',
  {},
  async ({ meta, ctx, params }) => {
    await deleteEvidence(ctx, params.evidenceId);
    return emptyResponse(meta);
  },
);
