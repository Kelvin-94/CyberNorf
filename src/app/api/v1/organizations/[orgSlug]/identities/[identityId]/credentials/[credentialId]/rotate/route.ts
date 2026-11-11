import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { rotateCredential } from '@/server/services/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; identityId: string; credentialId: string };

/**
 * Rotation revokes the old credential and issues a replacement with the same
 * name and scopes in one transaction. The plaintext replacement is returned
 * once and never recoverable afterwards.
 */
export const POST = withTenantApi<Params>('identity.manage', {}, async ({ meta, ctx, params }) => {
  const result = await rotateCredential(ctx, params.identityId, params.credentialId);
  return jsonResponse(result, meta, 201, { 'X-Identity-Credential-Issued': 'once' });
});
