import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { listIncidentAssignees, listIncidents } from '@/server/services/incidents';
import { loadTenantContext } from '@/server/ui/session';
import { enumSearchParam, searchParam } from '@/server/validation/common';
import {
  incidentQuerySchema,
  incidentSeveritySchema,
  incidentStatusSchema,
} from '@/server/validation/findings';

export const metadata: Metadata = { title: 'Incidents · CyberNorf' };
export const dynamic = 'force-dynamic';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'];

export default async function IncidentsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'incident.read');
  if (!ctx) {
    notFound();
  }

  const rawParams = await searchParams;
  // Unknown filter values fall back to "any" so a hand-edited URL cannot break
  // the page; the API keeps rejecting them with a 422.
  const query = incidentQuerySchema.parse({
    search: searchParam(rawParams, 'search'),
    status: enumSearchParam(rawParams, 'status', incidentStatusSchema),
    severity: enumSearchParam(rawParams, 'severity', incidentSeveritySchema),
  });

  const canCreate = can(ctx.membership.role, 'incident.create');
  const [result, assignees] = await Promise.all([
    listIncidents(ctx.organization.id, {
      search: query.search ?? null,
      ...(query.status ? { status: query.status } : {}),
      ...(query.severity ? { severity: query.severity } : {}),
      page: query.page,
      pageSize: query.pageSize,
      sort: query.sort,
      direction: query.direction,
    }),
    canCreate ? listIncidentAssignees(ctx.organization.id) : Promise.resolve([]),
  ]);

  const base = `/app/${ctx.organization.slug}`;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Response</p>
          <h1>Incidents</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {result.total} incident{result.total === 1 ? '' : 's'} matching the current filter
          </p>
        </div>
      </div>

      <form method="get" className="row" style={{ marginBottom: '1.25rem' }}>
        <label className="field" htmlFor="search" style={{ flex: '1 1 14rem' }}>
          Search
          <input id="search" name="search" defaultValue={query.search ?? ''} />
        </label>
        <label className="field" htmlFor="severity">
          Severity
          <select id="severity" name="severity" defaultValue={query.severity ?? ''}>
            <option value="">Any</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
          </select>
        </label>
        <label className="field" htmlFor="status">
          Status
          <select id="status" name="status" defaultValue={query.status ?? ''}>
            <option value="">Any</option>
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {status}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className="secondary">
          Filter
        </button>
      </form>

      <section className="card">
        {result.items.length === 0 ? (
          <p className="small muted">
            No incidents match. Open one below to start an investigation.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Detected</th>
                <th>Findings</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {result.items.map((incident) => (
                <tr key={incident.id}>
                  <td>
                    <Link href={`${base}/incidents/${incident.id}`}>{incident.title}</Link>
                    <div className="small muted">{incident.assignedTo?.name ?? 'Unassigned'}</div>
                  </td>
                  <td>
                    <span className={`badge ${incident.severity.toLowerCase()}`}>
                      {incident.severity}
                    </span>
                  </td>
                  <td className="small">{incident.status}</td>
                  <td className="mono small">
                    {incident.detectedAt.toISOString().slice(0, 16).replace('T', ' ')}
                  </td>
                  <td className="small">{incident.findingCount}</td>
                  <td className="small">{incident.noteCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canCreate ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Open an incident</h2>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/incidents`}
            fields={[
              { name: 'title', label: 'Title', required: true, maxLength: 200, full: true },
              {
                name: 'severity',
                label: 'Severity',
                type: 'select',
                defaultValue: 'MEDIUM',
                options: SEVERITIES.map((severity) => ({ value: severity, label: severity })),
              },
              {
                name: 'assignedToId',
                label: 'Owner',
                type: 'select',
                options: [
                  { value: '', label: 'Unassigned' },
                  ...assignees.map((member) => ({
                    value: member.id,
                    label: `${member.name} <${member.email}>`,
                  })),
                ],
              },
              {
                name: 'detectedAt',
                label: 'Detected at',
                type: 'datetime-local',
                help: 'Leave empty to use the current time.',
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                maxLength: 5000,
                full: true,
              },
            ]}
            submitLabel="Open incident"
            successMessage="Incident opened."
            resetOnSuccess
          />
        </section>
      ) : null}
    </>
  );
}
