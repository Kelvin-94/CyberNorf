import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { ENFORCEMENT_KINDS, ENFORCEMENT_STATES } from '@/server/domain/zero-trust';
import { listEnforcementActions } from '@/server/services/enforcement';
import { listConnectors } from '@/server/services/network';
import { loadTenantContext } from '@/server/ui/session';
import {
  connectorListQuerySchema,
  enforcementActionQuerySchema,
} from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Enforcement · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATE_BADGES: Record<string, string> = {
  REQUESTED: 'medium',
  APPROVED: 'info',
  REJECTED: 'low',
  DISPATCHED: 'low',
  ACKNOWLEDGED: 'info',
  VERIFIED: 'success',
  FAILED: 'critical',
  EXPIRED: 'high',
};

export default async function EnforcementPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'enforcement.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = enforcementActionQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    state: raw.state,
    kind: raw.kind,
    q: raw.q,
  });
  const query = parsed.success ? parsed.data : enforcementActionQuerySchema.parse({});

  const canManage = can(ctx.membership.role, 'enforcement.manage');
  const [actions, pending, failed, connectors] = await Promise.all([
    listEnforcementActions(ctx.organization.id, query),
    listEnforcementActions(
      ctx.organization.id,
      enforcementActionQuerySchema.parse({ state: 'REQUESTED', pageSize: 1 }),
    ),
    listEnforcementActions(
      ctx.organization.id,
      enforcementActionQuerySchema.parse({ state: 'FAILED', pageSize: 1 }),
    ),
    canManage
      ? listConnectors(ctx.organization.id, connectorListQuerySchema.parse({ pageSize: 100 }))
      : Promise.resolve({ connectors: [] }),
  ]);

  const base = `/app/${ctx.organization.slug}`;
  const page = actions.page;

  const filterParams = new URLSearchParams();
  for (const [key, value] of Object.entries({
    state: query.state,
    kind: query.kind,
    q: query.q,
  })) {
    if (value) {
      filterParams.set(key, value);
    }
  }
  const pageHref = (target: number) => {
    const next = new URLSearchParams(filterParams);
    next.set('page', String(target));
    return `${base}/enforcement?${next.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Zero trust</p>
          <h1>Enforcement</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Requests to act on a device, session or identity. A request is recorded first, approved
            by a second operator, then dispatched to a connector which acknowledges and verifies it.
            High-impact kinds always need a different approver than the requester.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Awaiting approval</p>
          <p className="stat-value">{pending.page.total}</p>
          <p className="small muted">Nobody can approve their own request</p>
        </div>
        <div className="stat">
          <p className="stat-label">Failed</p>
          <p className="stat-value">{failed.page.total}</p>
          <p className="small muted">Connector reported a failure</p>
        </div>
        <div className="stat">
          <p className="stat-label">Records</p>
          <p className="stat-value">{page.total}</p>
          <p className="small muted">Every request is retained</p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Actions</h2>
          <form method="get" className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
            <input
              name="q"
              defaultValue={query.q ?? ''}
              placeholder="Search target"
              aria-label="Search enforcement actions"
              style={{ width: '13rem' }}
            />
            <select name="state" defaultValue={query.state ?? ''} aria-label="State">
              <option value="">All states</option>
              {ENFORCEMENT_STATES.map((state) => (
                <option key={state} value={state}>
                  {state.toLowerCase()}
                </option>
              ))}
            </select>
            <select name="kind" defaultValue={query.kind ?? ''} aria-label="Kind">
              <option value="">All kinds</option>
              {ENFORCEMENT_KINDS.map((kind) => (
                <option key={kind} value={kind}>
                  {kind.replaceAll('_', ' ').toLowerCase()}
                </option>
              ))}
            </select>
            <button type="submit" className="secondary">
              Filter
            </button>
          </form>
        </div>

        {actions.actions.length === 0 ? (
          <p className="small muted" style={{ marginTop: '1rem' }}>
            No enforcement actions match. Requests raised from a device page or through the API land
            here.
          </p>
        ) : (
          <table className="data-table" style={{ marginTop: '1rem' }}>
            <thead>
              <tr>
                <th>Target</th>
                <th>Kind</th>
                <th>State</th>
                <th>Connector</th>
                <th>Requested</th>
              </tr>
            </thead>
            <tbody>
              {actions.actions.map((action) => (
                <tr key={action.id}>
                  <td>
                    <Link href={`${base}/enforcement/${action.id}`}>{action.targetLabel}</Link>
                    <p className="small muted" style={{ margin: '0.15rem 0 0' }}>
                      {action.targetType}
                    </p>
                  </td>
                  <td className="small">{action.kind.replaceAll('_', ' ').toLowerCase()}</td>
                  <td>
                    <span className={`badge ${STATE_BADGES[action.state] ?? ''}`}>
                      {action.state.toLowerCase()}
                    </span>
                    {action.expired ? ' expired' : ''}
                  </td>
                  <td className="small mono">{action.connectorId ?? '—'}</td>
                  <td className="small">{new Date(action.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '1rem' }}>
          <p className="small muted" style={{ margin: 0 }}>
            {page.total} action{page.total === 1 ? '' : 's'} · page {page.page} of {page.pageCount}
          </p>
          <div className="row" style={{ gap: '0.4rem' }}>
            {page.page > 1 ? (
              <Link className="nav-link" href={pageHref(page.page - 1)}>
                Previous
              </Link>
            ) : null}
            {page.page < page.pageCount ? (
              <Link className="nav-link" href={pageHref(page.page + 1)}>
                Next
              </Link>
            ) : null}
          </div>
        </div>
      </section>

      {canManage ? (
        <section className="card" style={{ marginTop: '1.5rem' }}>
          <h2>Request an action</h2>
          <p className="small muted">
            The request is created in <span className="mono">requested</span> state and does nothing
            until someone else approves it. The idempotency key is generated per page load, so a
            double submit returns the same action instead of creating a duplicate.
          </p>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/enforcement`}
            submitLabel="Raise request"
            successMessage="Request recorded. It needs approval from another operator before dispatch."
            resetOnSuccess={false}
            fields={[
              {
                name: 'kind',
                label: 'Kind',
                type: 'select',
                required: true,
                defaultValue: ENFORCEMENT_KINDS[0],
                options: ENFORCEMENT_KINDS.map((kind) => ({
                  value: kind,
                  label: kind.replaceAll('_', ' ').toLowerCase(),
                })),
              },
              {
                name: 'targetType',
                label: 'Target type',
                type: 'select',
                required: true,
                defaultValue: 'device',
                options: [
                  { value: 'device', label: 'device' },
                  { value: 'user', label: 'user' },
                  { value: 'session', label: 'session' },
                ],
              },
              {
                name: 'targetId',
                label: 'Target id',
                required: true,
                placeholder: 'Device or user id',
                help: 'Immutable id of the target, as shown on its detail page.',
              },
              {
                name: 'targetLabel',
                label: 'Display label',
                required: true,
                placeholder: 'e.g. KELVIN-MBP',
                help: 'Shown in this queue; does not have to be unique.',
              },
              {
                name: 'connectorId',
                label: 'Connector',
                type: 'select',
                allowEmpty: true,
                defaultValue: '',
                help: 'Required for kinds that execute on a network or endpoint connector.',
                options: connectors.connectors.map((connector) => ({
                  value: connector.id,
                  label: `${connector.name} (${connector.status.toLowerCase()})`,
                })),
              },
              {
                name: 'payload',
                label: 'Payload (JSON)',
                type: 'json',
                full: true,
                placeholder: '{ "blockSeconds": 900 }',
                help: 'Optional parameters passed to the connector verbatim.',
              },
              {
                name: 'reason',
                label: 'Reason',
                required: true,
                full: true,
                maxLength: 500,
                help: 'Recorded on the request and shown to the approver.',
              },
              {
                name: 'expiresInSeconds',
                label: 'Expires in (seconds)',
                type: 'number',
                min: 60,
                max: 86400,
                defaultValue: '3600',
                help: 'An unapproved request expires instead of lingering in the queue.',
              },
              {
                name: 'idempotencyKey',
                type: 'hidden',
                defaultValue: `ui-${crypto.randomUUID()}`,
              },
            ]}
          />
        </section>
      ) : null}
    </>
  );
}
