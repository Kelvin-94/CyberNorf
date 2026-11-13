import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getDeviceDetail, updateDevice } from '@/server/services/devices';
import { updateDeviceSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; deviceId: string };

export const GET = withTenantApi<Params>('device.read', {}, async ({ meta, ctx, params }) => {
  const detail = await getDeviceDetail(ctx.organization.id, params.deviceId);
  return jsonResponse(detail, meta);
});

export const PATCH = withTenantApi<Params>(
  'device.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = updateDeviceSchema.parse(await readJsonBody(request));
    const device = await updateDevice(ctx, params.deviceId, input);
    return jsonResponse({ device }, meta);
  },
);
