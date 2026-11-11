import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { issueCredential } from '@/server/services/identities';
import { issueIdentityCredentialSchema } from '@/server/validation/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; identityId: string };

export const POST = withTenantApi<Params>(
  'identity.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = issueIdentityCredentialSchema.parse(await readJsonBody(request));
    const result = await issueCredential(ctx, params.identityId, input);
    // The plaintext credential appears in this body exactly once; the header
    // tells clients and proxies never to cache or log it as a reusable value.
    return jsonResponse(result, meta, 201, { 'X-Identity-Credential-Issued': 'once' });
  },
);
