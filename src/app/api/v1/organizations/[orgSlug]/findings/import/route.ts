import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { importFindings } from '@/server/services/findings';
import { withoutUndefined } from '@/server/validation/common';
import { importFindingsSchema } from '@/server/validation/findings';

export const dynamic = 'force-dynamic';

/**
 * Bulk import of pre-normalized findings (for example the JSON export of a
 * scanner run). The importer deduplicates by fingerprint and never creates
 * assets implicitly, so unknown asset identifiers are reported per item.
 */
export const POST = withTenantApi(
  'finding.import',
  { rateLimit: { limit: 12, windowSeconds: 60, scope: 'user' } },
  async ({ request, meta, ctx }) => {
    const input = importFindingsSchema.parse(await readJsonBody(request, 1024 * 1024));
    const result = await importFindings(
      ctx,
      input.findings.map((item) => withoutUndefined(item)),
    );
    return jsonResponse(result, meta, 200);
  },
);
