import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { verifyEvidenceFile } from '@/server/services/evidence-files';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; controlId: string; evidenceId: string };

/**
 * Re-reads the stored artifact and compares it to the hash recorded at upload.
 *
 * A MISMATCH or MISSING is returned with 200 and the outcome in the body, not as
 * an error status: the check itself succeeded, and the caller needs the detail
 * (both hashes) to act on. A 500 would read as "the check failed to run".
 *
 * The verb is POST and the capability is the mutating `compliance.evidence`, not
 * `compliance.read`, because verification writes the outcome to the row and
 * appends an audit event. A read-only member must not be able to drive writes
 * or fill the tenant's audit chain by refreshing a page.
 */
export const POST = withTenantApi<Params>(
  'compliance.evidence',
  { rateLimit: { limit: 60, windowSeconds: 60 } },
  async ({ meta, ctx, params }) => {
    const result = await verifyEvidenceFile(ctx, params.evidenceId);
    return jsonResponse(result, meta);
  },
);
