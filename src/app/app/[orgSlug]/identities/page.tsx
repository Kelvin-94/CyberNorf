import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { IdentityCreateForm } from '@/components/identities/identity-create-form';
import { can } from '@/server/authz/roles';
import {
  CREDENTIAL_TTL_DEFAULT_DAYS,
  CREDENTIAL_TTL_MAX_DAYS,
  IDENTITY_CREDENTIAL_SCOPE_DETAILS,
  IDENTITY_CREDENTIAL_SCOPES,
  IDENTITY_TYPE_DETAILS,
  IDENTITY_TYPES,
} from '@/server/domain/identity';
import {
  getIdentityOverview,
  listAssignableMembers,
  listIdentities,
} from '@/server/services/identities';
import { loadTenantContext } from '@/server/ui/session';
import { identityListQuerySchema } from '@/server/validation/identities';

export const metadata: Metadata = { title: 'Identities · CyberNorf' };
export const dynamic = 'force-dynamic';

const STATUS_BADGES: Record<string, string> = {
  ACTIVE: 'success',
  PENDING_APPROVAL: 'medium',
  SUSPENDED: 'denied',
  DEPROVISIONED: 'low',
};

const RISK_BADGES: Record<string, string> = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

export default async function IdentitiesPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'identity.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = identityListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    kind: raw.kind,
    type: raw.type,
    status: raw.status,
    search: raw.search,
    sort: raw.sort,
    direction: raw.direction,
  });
  const query = parsed.success ? parsed.data : identityListQuerySchema.parse({});

  const canManage = can(ctx.membership.role, 'identity.manage');
  const [page, overview, members] = await Promise.all([
    listIdentities(ctx.organization.id, query),
    getIdentityOverview(ctx.organization.id),
    canManage ? listAssignableMembers(ctx.organization.id) : Promise.resolve([]),
  ]);

  const base = `/app/${ctx.organization.slug}`;
  const filterParams = new URLSearchParams();
  for (const [key, value] of Object.entries({
    search: query.search,
    kind: query.kind,
    status: query.status,
    sort: query.sort,
    direction: query.direction,
    pageSize: String(query.pageSize),
  })) {
    if (value) {
      filterParams.set(key, value);
    }
  }
  const pageHref = (target: number) => {
    const next = new URLSearchParams(filterParams);
    next.set('page', String(target));
    return `${base}/identities?${next.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Identity governance</p>
          <h1>Identities</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Humans, workloads, devices and service accounts with an accountable owner, an approval
            state and a credential policy. Console access still belongs to{' '}
            <Link href={`${base}/members`}>memberships</Link>; this inventory never grants it.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Total identities</p>
          <p className="stat-value">{overview.counts.total}</p>
          <p className="small muted">
            {overview.counts.human} human · {overview.counts.machine} non-human
          </p>
        </div>
        <div className="stat">
          <p className="stat-label">Awaiting owner approval</p>
          <p className="stat-value">{overview.attention.pendingApprovals}</p>
          <p className="small muted">Non-human identities that cannot authenticate yet</p>
        </div>
        <div className="stat">
          <p className="stat-label">Credentials expiring</p>
          <p className="stat-value">{overview.attention.expiringCredentials}</p>
          <p className="small muted">Within 30 days</p>
        </div>
        <div className="stat">
          <p className="stat-label">Needs attention</p>
          <p className="stat-value">{overview.attention.nonCompliantIdentities}</p>
          <p className="small muted">
            {overview.attention.unownedMachines} unowned ·{' '}
            {overview.attention.nonCompliantIdentities} dormant
          </p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Inventory</h2>
          <form method="get" className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
            <input
              name="search"
              defaultValue={query.search ?? ''}
              placeholder="Search name, identifier, department"
              aria-label="Search identities"
              style={{ width: '16rem' }}
            />
            <select name="kind" defaultValue={query.kind ?? ''} aria-label="Kind">
              <option value="">All kinds</option>
              <option value="HUMAN">Human</option>
              <option value="MACHINE">Non-human</option>
            </select>
            <select name="status" defaultValue={query.status ?? ''} aria-label="Status">
              <option value="">All statuses</option>
              <option value="PENDING_APPROVAL">Pending approval</option>
              <option value="ACTIVE">Active</option>
              <option value="SUSPENDED">Suspended</option>
              <option value="DEPROVISIONED">Deprovisioned</option>
            </select>
            <select name="sort" defaultValue={query.sort} aria-label="Sort">
              <option value="createdAt">Newest first</option>
              <option value="displayName">Name</option>
              <option value="lastSeenAt">Last seen</option>
              <option value="criticality">Criticality</option>
              <option value="status">Status</option>
            </select>
            <button type="submit" className="secondary">
              Filter
            </button>
            <Link href={`${base}/identities`} className="nav-link">
              Reset
            </Link>
          </form>
        </div>

        {page.items.length === 0 ? (
          <p className="small muted">
            No identities match this filter. {canManage ? 'Register one below.' : ''}
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Identity</th>
                <th>Kind / type</th>
                <th>Status</th>
                <th>Criticality</th>
                <th>Owner</th>
                <th>Risk</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((identity) => (
                <tr key={identity.id}>
                  <td>
                    <Link href={`${base}/identities/${identity.id}`}>{identity.displayName}</Link>
                    <div className="mono small muted">{identity.identifier}</div>
                  </td>
                  <td className="small">
                    {identity.kind === 'HUMAN' ? 'Human' : 'Non-human'}
                    <div className="muted">{identity.type.replaceAll('_', ' ').toLowerCase()}</div>
                  </td>
                  <td>
                    <span className={`badge ${STATUS_BADGES[identity.status] ?? ''}`}>
                      {identity.status.replaceAll('_', ' ').toLowerCase()}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${RISK_BADGES[identity.criticality] ?? ''}`}>
                      {identity.criticality.toLowerCase()}
                    </span>
                  </td>
                  <td className="small">
                    {identity.owner ? (
                      <>
                        {identity.owner.name}
                        <div className="muted">{identity.owner.email}</div>
                      </>
                    ) : (
                      <span className="badge medium">unowned</span>
                    )}
                  </td>
                  <td className="small">
                    <span className={`badge ${RISK_BADGES[identity.risk.level] ?? ''}`}>
                      {identity.risk.level.toLowerCase()} · {identity.risk.score}
                    </span>
                    {identity.risk.signals.length > 0 ? (
                      <div className="muted">{identity.risk.signals[0]?.detail}</div>
                    ) : null}
                  </td>
                  <td className="small">{formatDate(identity.lastSeenAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '0.75rem' }}>
          <span className="small muted">
            Page {page.pagination.page} of {page.pagination.pageCount} · {page.pagination.total}{' '}
            identities
          </span>
          <div className="row" style={{ gap: '0.4rem' }}>
            {page.pagination.page > 1 ? (
              <Link className="nav-link" href={pageHref(page.pagination.page - 1)}>
                Previous
              </Link>
            ) : null}
            {page.pagination.page < page.pagination.pageCount ? (
              <Link className="nav-link" href={pageHref(page.pagination.page + 1)}>
                Next
              </Link>
            ) : null}
          </div>
        </div>
      </section>

      {canManage ? (
        <details className="card" style={{ marginTop: '1.5rem' }}>
          <summary>
            <strong>Register an identity</strong>
          </summary>
          <p className="small muted">
            Non-human identities are created pending approval; an owner must approve them before a
            credential can be issued. Creating a human identity records the person for governance
            and does not add them to the organization.
          </p>
          <IdentityCreateForm
            action={`/api/v1/organizations/${ctx.organization.slug}/identities`}
            basePath={`${base}/identities`}
            members={members}
            types={IDENTITY_TYPES.map((type) => ({
              type,
              description: IDENTITY_TYPE_DETAILS[type],
              kind: type === 'USER' ? 'HUMAN' : 'MACHINE',
            }))}
            scopes={IDENTITY_CREDENTIAL_SCOPES.map((scope) => ({
              scope,
              description: IDENTITY_CREDENTIAL_SCOPE_DETAILS[scope],
            }))}
            defaultTtlDays={CREDENTIAL_TTL_DEFAULT_DAYS}
            ttlMaxDays={CREDENTIAL_TTL_MAX_DAYS}
          />
        </details>
      ) : null}
    </>
  );
}
