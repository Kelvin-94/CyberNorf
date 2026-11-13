import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { badRequest } from '@/server/errors';
import { readJsonBody } from '@/server/http/request-meta';
import { activateDevice, retireDevice, suspendDevice } from '@/server/services/devices';
import { deviceLifecycleSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; deviceId: string };

/**
 * Device lifecycle transitions share one endpoint because they are the same
 * decision with different destinations, and each one re-derives trust in the
 * same transaction as the status change.
 */
export const POST = withTenantApi<Params>(
  'device.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = deviceLifecycleSchema.parse(await readJsonBody(request));

    if (input.action === 'activate') {
      return jsonResponse({ device: await activateDevice(ctx, params.deviceId) }, meta);
    }

    if (input.reason === undefined || input.reason === null) {
      throw badRequest('Suspending or retiring a device requires a reason.');
    }

    const device =
      input.action === 'suspend'
        ? await suspendDevice(ctx, params.deviceId, input.reason)
        : await retireDevice(ctx, params.deviceId, input.reason);

    return jsonResponse({ device }, meta);
  },
);
