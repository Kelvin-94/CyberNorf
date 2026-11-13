import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { submitPosture } from '@/server/services/devices';
import { submitPostureSchema } from '@/server/validation/zero-trust';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; deviceId: string };

/**
 * Records a posture report. Trust is recomputed from the report immediately, so
 * the response carries the state the device is in now rather than the one it
 * was in when the report was queued.
 */
export const POST = withTenantApi<Params>(
  'device.manage',
  {},
  async ({ request, meta, ctx, params }) => {
    const input = submitPostureSchema.parse(await readJsonBody(request));
    const result = await submitPosture(ctx, params.deviceId, input);
    return jsonResponse(result, meta, 201);
  },
);
