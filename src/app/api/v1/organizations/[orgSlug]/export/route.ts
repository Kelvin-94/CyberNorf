import { securityHeaders, withTenantApi } from '@/server/api/handler';
import { exportOrganizationForDownload } from '@/server/services/export';
import { sanitiseFileName } from '@/server/services/evidence-storage';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Whole-organization export as a downloadable JSON document.
 *
 * Rate limiting is much tighter than a normal read because the cost is not one
 * query but fifteen across every tenant table, and the response can be very
 * large. The document is serialised in one pass: the export is already fully
 * materialised by the service, so streaming would save memory the service has
 * already spent.
 */
export const GET = withTenantApi<Params>(
  'export.download',
  { rateLimit: { limit: 5, windowSeconds: 300 } },
  async ({ meta, ctx, params }) => {
    const payload = await exportOrganizationForDownload(ctx);

    const stamp = payload.meta.exportedAt.replace(/[:.]/g, '-');
    const fileName = sanitiseFileName(`cybernorf-${params.orgSlug}-${stamp}.json`);

    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: securityHeaders(meta, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${fileName}"`,
        // The export contains the full audit trail and every member's email, so
        // it must never sit in a shared cache.
        'Cache-Control': 'private, no-store',
        'X-Export-Version': String(payload.meta.version),
      }),
    });
  },
);
