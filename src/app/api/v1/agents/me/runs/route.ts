import { withAgentApi } from '@/server/api/agent';
import { jsonResponse } from '@/server/api/handler';
import { readJsonBody } from '@/server/http/request-meta';
import { listAgentRuns, recordAgentRun } from '@/server/services/agents';
import { agentRunReportSchema } from '@/server/validation/agents';

export const dynamic = 'force-dynamic';

/** Recent runs reported by the calling agent, newest first. */
export const GET = withAgentApi('monitor.read', async ({ request, meta, agent }) => {
  const limitParam = new URL(request.url).searchParams.get('limit');
  const limit = limitParam ? Number.parseInt(limitParam, 10) : 20;
  const history = await listAgentRuns(agent, Number.isFinite(limit) ? limit : 20);
  return jsonResponse(history, meta);
});

/**
 * Accepts one monitoring run. A report is capped at 1 MiB because it carries
 * individual check results, not file contents, and the service derives every
 * count and finding from the submitted checks.
 */
export const POST = withAgentApi('monitor.report', async ({ request, meta, agent }) => {
  const report = agentRunReportSchema.parse(await readJsonBody(request, 1024 * 1024));
  const result = await recordAgentRun(agent, report);
  return jsonResponse(result, meta, 201);
});
