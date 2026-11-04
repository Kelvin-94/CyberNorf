import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { listComplianceFormOptions } from '@/server/services/compliance';

export const dynamic = 'force-dynamic';

/** Owners and evidence targets that the compliance forms can reference. */
export const GET = withTenantApi('compliance.read', {}, async ({ meta, ctx }) => {
  const options = await listComplianceFormOptions(ctx.organization.id);
  return jsonResponse(options, meta);
});
