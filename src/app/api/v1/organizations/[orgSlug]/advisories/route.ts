import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { importAdvisories, listAdvisories } from '@/server/services/software';
import { parseQuery } from '@/server/validation/common';
import { advisoryImportSchema, advisoryQuerySchema } from '@/server/validation/software';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * The advisory feed is the offline substitute for querying a vulnerability
 * database: an operator imports it, and every agent run is matched against it
 * without the platform making an outbound request.
 */
export const GET = withTenantApi<Params>('advisory.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, advisoryQuerySchema);
  const result = await listAdvisories(ctx, query);
  return jsonResponse(result, meta);
});

/**
 * Imports are capped (500 rows, 2 MiB) and idempotent on (identifier, package),
 * so an operator can re-import a corrected feed without creating duplicates.
 */
export const POST = withTenantApi<Params>('advisory.manage', {}, async ({ request, meta, ctx }) => {
  const input = advisoryImportSchema.parse(await readJsonBody(request, 2 * 1024 * 1024));
  const result = await importAdvisories(ctx, input);
  return jsonResponse(result, meta, 201);
});
