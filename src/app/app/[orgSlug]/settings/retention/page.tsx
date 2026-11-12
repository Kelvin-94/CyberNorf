import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import {
  DEFAULT_RETENTION_POLICY,
  RETENTION_POLICY_BOUNDS,
  getRetentionPolicy,
  planRetentionPolicy,
  type RetentionCategory,
  type RetentionPolicyPlan,
} from '@/server/services/retention';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Retention · CyberNorf' };
export const dynamic = 'force-dynamic';

const CATEGORY_COPY: Record<
  RetentionCategory,
  { label: string; description: string; countKey: keyof RetentionPolicyPlan['counts'] }
> = {
  agentRunDays: {
    label: 'Agent runs',
    description:
      'Check results reported by monitoring agents, and the history the console shows for each host.',
    countKey: 'runs',
  },
  notificationEventDays: {
    label: 'Alert deliveries',
    description:
      'Delivery attempts and their outcomes for alerts that have already reached a terminal state.',
    countKey: 'notificationEvents',
  },
  softwareItemDays: {
    label: 'Software inventory',
    description: 'Inventory rows that no agent has reported again inside the window.',
    countKey: 'softwareItems',
  },
  executionJobDays: {
    label: 'Execution jobs',
    description:
      'Finished, denied or cancelled controlled-execution records. Running jobs are never removed.',
    countKey: 'executionJobs',
  },
};

function formatWhen(value: string | null): string {
  return value ? new Date(value).toLocaleString() : 'never';
}

export default async function RetentionPage({ params }: { params: Promise<{ orgSlug: string }> }) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'retention.read');
  if (!ctx) {
    notFound();
  }

  const [effective, plan] = await Promise.all([
    getRetentionPolicy(ctx.organization.id),
    planRetentionPolicy(ctx.organization.id),
  ]);
  const canManage = can(ctx.membership.role, 'retention.manage');
  const canPurge = ctx.membership.role === 'OWNER';
  const totalDue = Object.values(plan.counts).reduce((sum, count) => sum + count, 0);
  const base = `/app/${ctx.organization.slug}`;
  const endpoint = `/api/v1/organizations/${ctx.organization.slug}/settings/retention`;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Governance</p>
          <h1>Retention</h1>
        </div>
        <Link href={`${base}/settings`} className="small muted">
          Back to settings
        </Link>
      </div>

      <section className="card stack">
        <h2>Current policy</h2>
        <p className="small muted">
          Each category has its own window. The policy applies to this organization only, and every
          change is written to the audit trail with the before and after values. When the deployment
          runs its retention timer, the stored policy is applied automatically; the sweep only
          touches organizations that have saved one.
        </p>
        <dl className="detail-grid">
          <div>
            <dt>Source</dt>
            <dd>
              {effective.customised ? 'Configured by this organization' : 'Platform defaults'}
            </dd>
          </div>
          <div>
            <dt>Last changed</dt>
            <dd>{formatWhen(effective.updatedAt)}</dd>
          </div>
          <div>
            <dt>Changed by</dt>
            <dd>{effective.updatedBy ? effective.updatedBy.name : '—'}</dd>
          </div>
          <div>
            <dt>Allowed range</dt>
            <dd className="mono">
              {RETENTION_POLICY_BOUNDS.minDays}–{RETENTION_POLICY_BOUNDS.maxDays} days
            </dd>
          </div>
        </dl>
      </section>

      <section className="card stack" style={{ marginTop: '1.5rem' }}>
        <h2>Preview of a purge now</h2>
        <p className="small muted">
          Read-only: this is what the stored policy would remove if the sweep ran right now.{' '}
          {totalDue === 0
            ? 'Nothing is past its window.'
            : `${totalDue} record${totalDue === 1 ? '' : 's'} are past their window.`}
        </p>
        <table className="data-table">
          <thead>
            <tr>
              <th>Category</th>
              <th>Window</th>
              <th>Cutoff</th>
              <th>Records past cutoff</th>
            </tr>
          </thead>
          <tbody>
            {(Object.keys(CATEGORY_COPY) as RetentionCategory[]).map((category) => {
              const copy = CATEGORY_COPY[category];
              const count = plan.counts[copy.countKey];
              return (
                <tr key={category}>
                  <td className="small">
                    {copy.label}
                    <div className="muted">{copy.description}</div>
                  </td>
                  <td className="mono small">{effective.policy[category]} days</td>
                  <td className="mono small">
                    {new Date(plan.cutoffs[category]).toISOString().slice(0, 10)}
                  </td>
                  <td className="mono small">{count}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="small muted">
          The audit trail, findings, incidents and evidence are not part of this policy: they are
          the record of what happened, not derived history. Defaults are{' '}
          {Object.entries(DEFAULT_RETENTION_POLICY)
            .map(
              ([category, days]) =>
                `${CATEGORY_COPY[category as RetentionCategory].label} ${days}d`,
            )
            .join(', ')}
          .
        </p>
      </section>

      <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
        <h2>Change the windows</h2>
        {canManage ? (
          <ActionForm
            action={endpoint}
            method="PUT"
            fields={(Object.keys(CATEGORY_COPY) as RetentionCategory[]).map((category) => ({
              name: category,
              label: `${CATEGORY_COPY[category].label} (days)`,
              type: 'number' as const,
              required: true,
              min: RETENTION_POLICY_BOUNDS.minDays,
              max: RETENTION_POLICY_BOUNDS.maxDays,
              step: 1,
              defaultValue: String(effective.policy[category]),
              help: CATEGORY_COPY[category].description,
              full: true,
            }))}
            submitLabel="Save policy"
            successMessage="Retention policy updated."
          />
        ) : (
          <p className="banner">
            Your role can read the policy but not change it. Ask an owner or administrator.
          </p>
        )}
      </section>

      {canPurge ? (
        <section className="card stack" style={{ marginTop: '1.5rem', maxWidth: '44rem' }}>
          <h2>Purge retained history</h2>
          <p className="banner warning">
            This deletes the {totalDue} record{totalDue === 1 ? '' : 's'} past their window and
            cannot be undone. The counts are recorded in the audit trail, which is kept.
          </p>
          <ActionForm
            action={`${endpoint}/purge`}
            fields={[
              {
                name: 'confirm',
                label: 'Confirmation',
                type: 'text',
                required: true,
                maxLength: 5,
                placeholder: 'PURGE',
                help: 'Type PURGE to confirm. The server refuses anything else.',
                full: true,
              },
            ]}
            submitLabel="Purge now"
            successMessage="Retained history purged. The audit trail records the counts."
          />
        </section>
      ) : (
        <p className="banner" style={{ marginTop: '1.5rem' }}>
          Only an owner can purge retained history. Administrators can change the policy.
        </p>
      )}
    </>
  );
}
