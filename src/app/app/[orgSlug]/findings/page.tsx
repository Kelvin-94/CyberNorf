import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { ImportFindingsForm } from '@/components/findings/import-findings-form';
import { can } from '@/server/authz/roles';
import { remediationState } from '@/server/domain/risk';
import { listFindingFormOptions, listFindings } from '@/server/services/findings';
import { loadTenantContext } from '@/server/ui/session';
import type { FindingStatus } from '@/generated/prisma/client';
import { enumSearchParam, searchParam } from '@/server/validation/common';
import {
  findingQuerySchema,
  findingSeveritySchema,
  findingStatusSchema,
} from '@/server/validation/findings';

export const metadata: Metadata = { title: 'Findings · CyberNorf' };
export const dynamic = 'force-dynamic';

/**
 * Renders the remediation deadline with its state. The date is always shown so
 * an analyst who has no badge still sees when the clock runs out.
 */
function DueBadge({ dueAt, status }: { dueAt: Date | null; status: FindingStatus }) {
  const state = remediationState({ dueAt, status });
  if (!dueAt) {
    return <span className="muted">—</span>;
  }
  const formatted = dueAt.toISOString().slice(0, 10);
  return (
    <span>
      <span className={`badge ${state === 'OVERDUE' ? 'critical' : 'neutral'}`}>
        {state.replaceAll('_', ' ').toLowerCase()}
      </span>
      <div className="mono muted">{formatted}</div>
    </span>
  );
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STATUSES = ['OPEN', 'TRIAGED', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'];

export default async function FindingsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'finding.read');
  if (!ctx) {
    notFound();
  }

  const rawParams = await searchParams;
  // Unknown filter values fall back to "any" so a hand-edited URL cannot break
  // the page; the API keeps rejecting them with a 422.
  const query = findingQuerySchema.parse({
    search: searchParam(rawParams, 'search'),
    severity: enumSearchParam(rawParams, 'severity', findingSeveritySchema),
    status: enumSearchParam(rawParams, 'status', findingStatusSchema),
    overdue: searchParam(rawParams, 'overdue'),
  });

  const [result, options] = await Promise.all([
    listFindings(ctx.organization.id, {
      search: query.search ?? null,
      ...(query.severity ? { severity: query.severity } : {}),
      ...(query.status ? { status: query.status } : {}),
      overdue: query.overdue ?? false,
      page: query.page,
      pageSize: query.pageSize,
      sort: query.sort,
      direction: query.direction,
    }),
    listFindingFormOptions(ctx.organization.id),
  ]);

  const base = `/app/${ctx.organization.slug}`;
  const endpoint = `/api/v1/organizations/${ctx.organization.slug}/findings`;
  const canCreate = can(ctx.membership.role, 'finding.create');
  const canImport = can(ctx.membership.role, 'finding.import');

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Vulnerability management</p>
          <h1>Findings</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {result.total} finding{result.total === 1 ? '' : 's'} matching the current filter
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
                {status.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
        </label>
        <label className="field" htmlFor="overdue" style={{ alignSelf: 'end' }}>
          <span>
            <input
              id="overdue"
              name="overdue"
              type="checkbox"
              value="true"
              defaultChecked={query.overdue ?? false}
            />{' '}
            Overdue only
          </span>
        </label>
        <button type="submit" className="secondary">
          Filter
        </button>
      </form>

      <section className="card">
        {result.items.length === 0 ? (
          <p className="small muted">
            No findings match. Record one below or import a scanner export.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Remediation</th>
                <th>Status</th>
                <th>Asset</th>
                <th>Owner</th>
              </tr>
            </thead>
            <tbody>
              {result.items.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <Link href={`${base}/findings/${finding.id}`}>{finding.title}</Link>
                    {finding.cveId ? <div className="mono muted">{finding.cveId}</div> : null}
                  </td>
                  <td>
                    <span className={`badge ${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="mono small">{finding.riskScore}</td>
                  <td className="small">
                    <DueBadge dueAt={finding.dueAt} status={finding.status} />
                  </td>
                  <td className="small">{finding.status.replaceAll('_', ' ')}</td>
                  <td className="small">{finding.asset?.name ?? '—'}</td>
                  <td className="small">{finding.assignedTo?.name ?? 'Unassigned'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canCreate ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Record a finding</h2>
          <ActionForm
            action={endpoint}
            fields={[
              { name: 'title', label: 'Title', required: true, maxLength: 200, full: true },
              {
                name: 'severity',
                label: 'Severity',
                type: 'select',
                defaultValue: 'HIGH',
                options: SEVERITIES.map((severity) => ({ value: severity, label: severity })),
              },
              {
                name: 'assetId',
                label: 'Asset',
                type: 'select',
                options: [
                  { value: '', label: 'No asset' },
                  ...options.assets.map((asset) => ({ value: asset.id, label: asset.name })),
                ],
              },
              {
                name: 'assignedToId',
                label: 'Owner',
                type: 'select',
                options: [
                  { value: '', label: 'Unassigned' },
                  ...options.members.map((member) => ({ value: member.id, label: member.name })),
                ],
              },
              { name: 'cveId', label: 'CVE', placeholder: 'CVE-2026-12345' },
              {
                name: 'cvssScore',
                label: 'CVSS score',
                type: 'number',
                min: 0,
                max: 10,
                step: 0.1,
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                maxLength: 5000,
                full: true,
              },
              {
                name: 'remediation',
                label: 'Remediation',
                type: 'textarea',
                maxLength: 5000,
                full: true,
              },
            ]}
            submitLabel="Create finding"
            successMessage="Finding created."
            resetOnSuccess
          />
        </section>
      ) : null}

      {canImport ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Import findings</h2>
          <p className="small muted">
            Paste a JSON document of the form{' '}
            <code>{'{"findings": [{"title": "...", "severity": "HIGH"}]}'}</code>. Re-imports update
            the last-seen timestamp instead of duplicating findings.
          </p>
          <ImportFindingsForm action={`${endpoint}/import`} />
        </section>
      ) : null}
    </>
  );
}
