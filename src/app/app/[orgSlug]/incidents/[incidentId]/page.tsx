import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { StatusControl } from '@/components/status-control';
import { can } from '@/server/authz/roles';
import { allowedIncidentTransitions } from '@/server/domain/transitions';
import { AppError } from '@/server/errors';
import { getIncidentDetail, listIncidentAssignees } from '@/server/services/incidents';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Incident · CyberNorf' };
export const dynamic = 'force-dynamic';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default async function IncidentDetailPage({
  params,
}: {
  params: Promise<{ orgSlug: string; incidentId: string }>;
}) {
  const { orgSlug, incidentId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'incident.read');
  if (!ctx) {
    notFound();
  }

  let incident;
  try {
    incident = await getIncidentDetail(ctx, incidentId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }

  const canUpdate = can(ctx.membership.role, 'incident.update');
  const canNote = can(ctx.membership.role, 'incident.note');
  const assignees = canUpdate ? await listIncidentAssignees(ctx.organization.id) : [];

  const base = `/app/${ctx.organization.slug}`;
  const endpoint = `/api/v1/organizations/${ctx.organization.slug}/incidents/${incident.id}`;
  const transitions = allowedIncidentTransitions(incident.status);

  return (
    <>
      <p className="small muted">
        <Link href={`${base}/incidents`}>← Incidents</Link>
      </p>

      <div className="page-header">
        <div>
          <p className="eyebrow">Incident</p>
          <h1>{incident.title}</h1>
        </div>
        <div className="row">
          <span className={`badge ${incident.severity.toLowerCase()}`}>{incident.severity}</span>
          <span className="badge">{incident.status}</span>
        </div>
      </div>

      <section className="card">
        <dl className="detail-grid">
          <div>
            <dt>Owner</dt>
            <dd>{incident.assignedTo?.name ?? 'Unassigned'}</dd>
          </div>
          <div>
            <dt>Detected</dt>
            <dd className="mono">
              {incident.detectedAt.toISOString().slice(0, 16).replace('T', ' ')}
            </dd>
          </div>
          <div>
            <dt>Resolved</dt>
            <dd className="mono">
              {incident.resolvedAt
                ? incident.resolvedAt.toISOString().slice(0, 16).replace('T', ' ')
                : '—'}
            </dd>
          </div>
          <div>
            <dt>Closed</dt>
            <dd className="mono">
              {incident.closedAt
                ? incident.closedAt.toISOString().slice(0, 16).replace('T', ' ')
                : '—'}
            </dd>
          </div>
          <div>
            <dt>Opened by</dt>
            <dd>{incident.createdBy.name}</dd>
          </div>
          <div>
            <dt>Linked findings</dt>
            <dd>{incident._count.findings}</dd>
          </div>
        </dl>
        {incident.description ? (
          <p style={{ whiteSpace: 'pre-wrap', marginTop: '1rem' }}>{incident.description}</p>
        ) : null}
      </section>

      {canUpdate ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Status</h2>
          <StatusControl
            action={`${endpoint}/status`}
            current={incident.status}
            transitions={[...transitions]}
            withNote
          />
        </section>
      ) : null}

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Linked findings</h2>
        <p className="small muted">
          Link or unlink a finding from its detail page; each link is recorded in the audit trail.
        </p>
        {incident.findings.length === 0 ? (
          <p className="small muted">No findings linked to this incident.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Severity</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {incident.findings.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <Link href={`${base}/findings/${finding.id}`}>{finding.title}</Link>
                  </td>
                  <td>
                    <span className={`badge ${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="small">{finding.status.replaceAll('_', ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Investigation notes</h2>
        {incident.notes.length === 0 ? (
          <p className="small muted">No notes yet.</p>
        ) : (
          <ul className="stack" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {incident.notes.map((note) => (
              <li key={note.id} className="note">
                <div className="small muted">
                  {note.author.name} · {note.createdAt.toISOString().slice(0, 16).replace('T', ' ')}
                </div>
                <p style={{ whiteSpace: 'pre-wrap', margin: '0.25rem 0 0' }}>{note.body}</p>
              </li>
            ))}
          </ul>
        )}

        {canNote ? (
          <div style={{ marginTop: '1.25rem' }}>
            <ActionForm
              action={`${endpoint}/notes`}
              fields={[
                {
                  name: 'body',
                  label: 'Add a note',
                  type: 'textarea',
                  required: true,
                  full: true,
                  maxLength: 5000,
                },
              ]}
              submitLabel="Add note"
              successMessage="Note added."
              resetOnSuccess
              compact
            />
          </div>
        ) : null}
      </section>

      {canUpdate ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Edit incident</h2>
          <ActionForm
            action={endpoint}
            method="PATCH"
            fields={[
              {
                name: 'title',
                label: 'Title',
                defaultValue: incident.title,
                required: true,
                maxLength: 200,
                full: true,
              },
              {
                name: 'severity',
                label: 'Severity',
                type: 'select',
                defaultValue: incident.severity,
                options: SEVERITIES.map((severity) => ({ value: severity, label: severity })),
              },
              {
                name: 'assignedToId',
                label: 'Owner',
                type: 'select',
                defaultValue: incident.assignedTo?.id ?? '',
                options: [
                  { value: '', label: 'Unassigned' },
                  ...assignees.map((member) => ({
                    value: member.id,
                    label: `${member.name} <${member.email}>`,
                  })),
                ],
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                defaultValue: incident.description ?? '',
                maxLength: 5000,
                full: true,
              },
            ]}
            submitLabel="Save changes"
            successMessage="Incident updated."
          />
        </section>
      ) : null}

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Timeline</h2>
        {incident.history.length === 0 ? (
          <p className="small muted">No audit entries recorded yet.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Actor</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {incident.history.map((event) => (
                <tr key={event.id}>
                  <td className="mono small">
                    {event.createdAt.toISOString().slice(0, 16).replace('T', ' ')}
                  </td>
                  <td className="mono small">{event.action}</td>
                  <td className="small">{event.outcome}</td>
                  <td className="small">{event.actor?.name ?? event.actorType}</td>
                  <td className="small">{event.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
