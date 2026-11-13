import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { evaluateRequest } from '@/server/services/policy';
import { evaluationRequestSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * The central decision point. Evaluation is an operator action because every
 * call persists a decision record with the facts behind the verdict.
 */
export const POST = withTenantApi<Params>('policy.manage', {}, async ({ request, meta, ctx }) => {
  const input = evaluationRequestSchema.parse(await readJsonBody(request));
  const evaluated = await evaluateRequest(ctx.organization.id, input);
  return jsonResponse(evaluated, meta, 201);
});
