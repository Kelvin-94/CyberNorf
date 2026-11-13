import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { getDeviceOverview, listDevices, registerDevice } from '@/server/services/devices';
import { parseQuery } from '@/server/validation/common';
import { deviceListQuerySchema, registerDeviceSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string };

export const GET = withTenantApi<Params>('device.read', {}, async ({ request, meta, ctx }) => {
  const query = parseQuery(request, deviceListQuerySchema);
  const [page, overview] = await Promise.all([
    listDevices(ctx.organization.id, query),
    getDeviceOverview(ctx.organization.id),
  ]);
  return jsonResponse({ ...page, overview }, meta);
});

export const POST = withTenantApi<Params>('device.manage', {}, async ({ request, meta, ctx }) => {
  const input = registerDeviceSchema.parse(await readJsonBody(request));
  const device = await registerDevice(ctx, input);
  return jsonResponse({ device }, meta, 201);
});
