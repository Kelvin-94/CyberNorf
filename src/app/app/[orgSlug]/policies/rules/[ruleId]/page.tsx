import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { POLICY_EFFECTS } from '@/server/domain/zero-trust';
import { AppError } from '@/server/errors';
import { getPolicyRule } from '@/server/services/policy';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Policy rule · CyberNorf' };
export const dynamic = 'force-dynamic';

const EFFECT_BADGES: Record<string, string> = {
  ALLOW: 'success',
  DENY: 'critical',
  STEP_UP: 'medium',
  QUARANTINE: 'high',
};

export default async function PolicyRulePage({
  params,
}: {
  params: Promise<{ orgSlug: string; ruleId: string }>;
}) {
  const { orgSlug, ruleId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'policy.read');
  if (!ctx) {
    notFound();
  }

  let rule;
  try {
    rule = await getPolicyRule(ctx.organization.id, ruleId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }
  const canManage = can(ctx.membership.role, 'policy.manage');
  const base = `/app/${ctx.organization.slug}`;
  const rulePath = `/api/v1/organizations/${ctx.organization.slug}/policies/rules/${rule.id}`;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/policies`}>Policies</Link>
          </p>
          <h1>{rule.name}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Priority {rule.priority} · updated {new Date(rule.updatedAt).toLocaleString()}
          </p>
        </div>
        <div className="row" style={{ gap: '0.4rem' }}>
          <span className={`badge ${EFFECT_BADGES[rule.effect] ?? ''}`}>
            {rule.effect.replaceAll('_', ' ').toLowerCase()}
          </span>
          <span className={`badge ${rule.enabled ? 'success' : 'low'}`}>
            {rule.enabled ? 'enabled' : 'disabled'}
          </span>
        </div>
      </div>

      {rule.description ? (
        <p className="small muted" style={{ marginBottom: '1.25rem' }}>
          {rule.description}
        </p>
      ) : null}

      <section className="card">
        <h2>Conditions</h2>
        <p className="small muted">
          A request matches when every condition below holds. Conditions are ANDed; listing several
          values inside one condition accepts any of them.
        </p>
        <pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
          {JSON.stringify(rule.conditions, null, 2)}
        </pre>
      </section>

      {canManage ? (
        <>
          <section className="card" style={{ marginTop: '1.5rem' }}>
            <h2>Edit rule</h2>
            <p className="small muted">
              Disabling a rule removes it from evaluation without deleting its history. Updates are
              recorded in the audit trail with the fields that changed.
            </p>
            <ActionForm
              action={rulePath}
              method="PATCH"
              submitLabel="Save rule"
              successMessage="Rule updated."
              fields={[
                { name: 'name', label: 'Name', defaultValue: rule.name },
                {
                  name: 'description',
                  label: 'Description',
                  type: 'textarea',
                  full: true,
                  defaultValue: rule.description ?? '',
                },
                {
                  name: 'priority',
                  label: 'Priority',
                  type: 'number',
                  defaultValue: String(rule.priority),
                },
                {
                  name: 'effect',
                  label: 'Effect',
                  type: 'select',
                  defaultValue: rule.effect,
                  options: POLICY_EFFECTS.map((effect) => ({
                    value: effect,
                    label: effect.replaceAll('_', ' ').toLowerCase(),
                  })),
                },
                {
                  name: 'enabled',
                  label: 'Enabled',
                  type: 'checkbox',
                  defaultValue: rule.enabled ? 'true' : 'false',
                },
                {
                  name: 'conditions',
                  label: 'Conditions',
                  type: 'json',
                  full: true,
                  defaultValue: JSON.stringify(rule.conditions, null, 2),
                },
              ]}
            />
          </section>

          <section className="card" style={{ marginTop: '1.5rem' }}>
            <h2>Delete</h2>
            <p className="small muted">
              Deleting a rule removes it immediately. Decisions that already referenced it keep the
              stored explanation, so an audit of past verdicts remains accurate.
            </p>
            <ActionButton
              action={rulePath}
              method="DELETE"
              label="Delete rule"
              variant="danger"
              confirmText={`Delete the rule “${rule.name}”? This cannot be undone.`}
              redirectTo={`${base}/policies`}
            />
          </section>
        </>
      ) : null}
    </>
  );
}
