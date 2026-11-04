import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { adoptFramework, listFrameworks } from '@/server/services/compliance';
import { adoptFrameworkSchema } from '@/server/validation/compliance';

export const dynamic = 'force-dynamic';

/** Global catalog plus this tenant's adoption state for each framework. */
export const GET = withTenantApi('compliance.read', {}, async ({ meta, ctx }) => {
  const frameworks = await listFrameworks(ctx.organization.id);
  return jsonResponse({ frameworks }, meta);
});

export const POST = withTenantApi('compliance.manage', {}, async ({ request, meta, ctx }) => {
  const input = adoptFrameworkSchema.parse(await readJsonBody(request));
  const adoption = await adoptFramework(ctx, {
    frameworkId: input.frameworkId,
    targetDate: input.targetDate ?? null,
  });
  return jsonResponse({ adoption }, meta, 201);
});
