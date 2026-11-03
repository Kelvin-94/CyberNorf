import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { getAuditIntegrityReport } from '@/server/services/audit';

export const dynamic = 'force-dynamic';

/**
 * Recomputes the per-tenant hash chain. A failure means a row changed outside
 * the application, because the database trigger blocks in-place updates and
 * deletes on audit_events.
 */
export const GET = withTenantApi(
  'audit.read',
  { rateLimit: { limit: 20, windowSeconds: 60, scope: 'user' } },
  async ({ meta, ctx }) => {
    const report = await getAuditIntegrityReport(ctx);
    return jsonResponse(report, meta);
  },
);
