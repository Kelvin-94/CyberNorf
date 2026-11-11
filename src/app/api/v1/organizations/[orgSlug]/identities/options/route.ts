import { jsonResponse, withTenantApi } from '@/server/api/handler';
import {
  CREDENTIAL_TTL_DEFAULT_DAYS,
  CREDENTIAL_TTL_MAX_DAYS,
  CREDENTIAL_TTL_MIN_DAYS,
  IDENTITY_CREDENTIAL_SCOPE_DETAILS,
  IDENTITY_CREDENTIAL_SCOPES,
  IDENTITY_TYPES,
  IDENTITY_TYPE_DETAILS,
} from '@/server/domain/identity';
import { listAssignableMembers } from '@/server/services/identities';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

/**
 * Everything a create/edit form needs, resolved server-side so the browser does
 * not hard-code the scope catalog or the member list.
 */
export const GET = withTenantApi<Params>('identity.read', {}, async ({ meta, ctx }) => {
  const members = await listAssignableMembers(ctx.organization.id);
  return jsonResponse(
    {
      members,
      types: IDENTITY_TYPES.map((type) => ({
        type,
        description: IDENTITY_TYPE_DETAILS[type],
        kind: type === 'USER' ? 'HUMAN' : 'MACHINE',
      })),
      scopes: IDENTITY_CREDENTIAL_SCOPES.map((scope) => ({
        scope,
        description: IDENTITY_CREDENTIAL_SCOPE_DETAILS[scope],
      })),
      credentialTtl: {
        minDays: CREDENTIAL_TTL_MIN_DAYS,
        maxDays: CREDENTIAL_TTL_MAX_DAYS,
        defaultDays: CREDENTIAL_TTL_DEFAULT_DAYS,
      },
    },
    meta,
  );
});
