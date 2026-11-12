import { securityHeaders, withTenantApi } from '@/server/api/handler';
import { buildEvidencePackage } from '@/server/services/evidence-package';
import { sanitiseFileName } from '@/server/services/evidence-storage';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Signed, portable evidence package: the full export plus per-document digests,
 * an HMAC-SHA256 signature over a canonical manifest, and the audit-chain head
 * at signing time. Verification needs only this file and the shared key, so an
 * auditor does not need an account on the tenant.
 *
 * Rate limiting matches the plain export: the cost is every tenant table, and
 * each call also appends an audit event.
 */
export const GET = withTenantApi<Params>(
  'export.download',
  { rateLimit: { limit: 3, windowSeconds: 300 } },
  async ({ meta, ctx, params }) => {
    const pkg = await buildEvidencePackage(ctx);
    const stamp = pkg.manifest.createdAt.replace(/[:.]/g, '-');
    const fileName = sanitiseFileName(`cybernorf-${params.orgSlug}-evidence-${stamp}.json`);

    return new Response(JSON.stringify(pkg), {
      status: 200,
      headers: securityHeaders(meta, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${fileName}"`,
        'Cache-Control': 'private, no-store',
        'X-Evidence-Package-Id': pkg.manifest.packageId,
        'X-Evidence-Key-Id': pkg.manifest.keyId,
      }),
    });
  },
);
