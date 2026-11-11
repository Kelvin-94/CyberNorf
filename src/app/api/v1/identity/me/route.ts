import { withMachineIdentityApi } from '@/server/api/identity';
import { jsonResponse } from '@/server/api/handler';
import { describeMachineIdentity } from '@/server/services/identities';
import { unauthenticated } from '@/server/errors';

export const dynamic = 'force-dynamic';

/**
 * Self-description for a non-human identity. The credential can only read the
 * identity it belongs to and its own credential metadata; there is no endpoint
 * that lets it enumerate the inventory or reach another tenant.
 */
export const GET = withMachineIdentityApi('identity.self.read', async ({ meta, identity }) => {
  const view = await describeMachineIdentity(identity);
  if (!view) {
    // The credential was revoked between authentication and this read.
    throw unauthenticated();
  }
  return jsonResponse(view, meta);
});
