import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/components/action-form';
import { can } from '@/server/authz/roles';
import { POLICY_EFFECTS, ZONES } from '@/server/domain/zero-trust';
import { getPolicyOverview, listPolicyDecisions, listPolicyRules } from '@/server/services/policy';
import { loadTenantContext } from '@/server/ui/session';
import {
  policyDecisionListQuerySchema,
  policyRuleListQuerySchema,
} from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Policies · CyberNorf' };
export const dynamic = 'force-dynamic';

const EFFECT_BADGES: Record<string, string> = {
  ALLOW: 'success',
  DENY: 'critical',
  STEP_UP: 'medium',
  QUARANTINE: 'high',
};

function formatTimestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—';
}

function describeConditions(conditions: Record<string, unknown>): string {
  const entries = Object.entries(conditions);
  if (entries.length === 0) {
    return 'no conditions';
  }
  return entries
    .map(([key, value]) => {
      const rendered = Array.isArray(value) ? value.join(', ') : String(value);
      return `${key}=${rendered}`;
    })
    .join(' · ');
}

export default async function PoliciesPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'policy.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = policyRuleListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    effect: raw.effect,
    enabled: raw.enabled,
    q: raw.q,
  });
  const query = parsed.success ? parsed.data : policyRuleListQuerySchema.parse({});

  const decisionQuery = policyDecisionListQuerySchema.parse({ pageSize: 10 });
  const canManage = can(ctx.membership.role, 'policy.manage');
  const [rules, overview, decisions] = await Promise.all([
    listPolicyRules(ctx.organization.id, query),
    getPolicyOverview(ctx.organization.id),
    listPolicyDecisions(ctx.organization.id, decisionQuery),
  ]);

  const base = `/app/${ctx.organization.slug}`;
  const filterParams = new URLSearchParams();
  for (const [key, value] of Object.entries({
    effect: query.effect,
    enabled: query.enabled === undefined ? undefined : String(query.enabled),
    q: query.q,
    pageSize: String(query.pageSize),
  })) {
    if (value) {
      filterParams.set(key, value);
    }
  }
  const pageHref = (target: number) => {
    const next = new URLSearchParams(filterParams);
    next.set('page', String(target));
    return `${base}/policies?${next.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Zero trust</p>
          <h1>Policies</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Ordered rules evaluated against server-resolved facts. The first matching rule wins;
            when nothing matches the request is denied. Changes take effect on the next evaluation,
            and every verdict is stored with the facts it was made from.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="stat">
          <p className="stat-label">Rules</p>
          <p className="stat-value">{overview.rules.total}</p>
          <p className="small muted">{overview.rules.enabled} enabled</p>
        </div>
        <div className="stat">
          <p className="stat-label">Decisions (24h)</p>
          <p className="stat-value">{overview.decisions24h.total}</p>
          <p className="small muted">Last at {formatTimestamp(overview.lastDecisionAt)}</p>
        </div>
        <div className="stat">
          <p className="stat-label">Allowed</p>
          <p className="stat-value">{overview.decisions24h.allowed}</p>
          <p className="small muted">{overview.decisions24h.denied} denied</p>
        </div>
        <div className="stat">
          <p className="stat-label">Held for review</p>
          <p className="stat-value">
            {overview.decisions24h.stepUp + overview.decisions24h.quarantine}
          </p>
          <p className="small muted">
            {overview.decisions24h.stepUp} step-up · {overview.decisions24h.quarantine} quarantine
          </p>
        </div>
      </div>

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Rules</h2>
          <form method="get" className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
            <input
              name="q"
              defaultValue={query.q ?? ''}
              placeholder="Search name or description"
              aria-label="Search rules"
              style={{ width: '16rem' }}
            />
            <select name="effect" defaultValue={query.effect ?? ''} aria-label="Effect">
              <option value="">All effects</option>
              {POLICY_EFFECTS.map((effect) => (
                <option key={effect} value={effect}>
                  {effect.replaceAll('_', ' ').toLowerCase()}
                </option>
              ))}
            </select>
            <select
              name="enabled"
              defaultValue={query.enabled === undefined ? '' : String(query.enabled)}
              aria-label="Enabled"
            >
              <option value="">Enabled and disabled</option>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
            <button type="submit" className="secondary">
              Filter
            </button>
            <Link href={`${base}/policies`} className="nav-link">
              Reset
            </Link>
          </form>
        </div>

        {rules.rules.length === 0 ? (
          <p className="small muted">
            No rules yet. Every request is denied until an ALLOW rule matches, which is the safe
            default but will block legitimate access.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Rule</th>
                <th>Effect</th>
                <th>Conditions</th>
                <th>State</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {rules.rules.map((rule) => (
                <tr key={rule.id}>
                  <td className="mono small">{rule.priority}</td>
                  <td>
                    <Link href={`${base}/policies/rules/${rule.id}`}>{rule.name}</Link>
                    {rule.description ? (
                      <div className="small muted">{rule.description}</div>
                    ) : null}
                  </td>
                  <td>
                    <span className={`badge ${EFFECT_BADGES[rule.effect] ?? ''}`}>
                      {rule.effect.replaceAll('_', ' ').toLowerCase()}
                    </span>
                  </td>
                  <td className="small mono" style={{ maxWidth: '26rem', wordBreak: 'break-word' }}>
                    {describeConditions(rule.conditions)}
                  </td>
                  <td>
                    <span className={`badge ${rule.enabled ? 'success' : 'low'}`}>
                      {rule.enabled ? 'enabled' : 'disabled'}
                    </span>
                  </td>
                  <td className="small">{formatTimestamp(rule.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '0.75rem' }}>
          <span className="small muted">
            Page {rules.page.page} of {rules.page.pageCount} · {rules.page.total} rules
          </span>
          <div className="row" style={{ gap: '0.4rem' }}>
            {rules.page.page > 1 ? (
              <Link className="nav-link" href={pageHref(rules.page.page - 1)}>
                Previous
              </Link>
            ) : null}
            {rules.page.page < rules.page.pageCount ? (
              <Link className="nav-link" href={pageHref(rules.page.page + 1)}>
                Next
              </Link>
            ) : null}
          </div>
        </div>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2>Recent decisions</h2>
          <Link href={`${base}/policies/decisions`} className="nav-link">
            All decisions
          </Link>
        </div>
        {decisions.decisions.length === 0 ? (
          <p className="small muted">No decision has been recorded yet.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Subject</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Verdict</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {decisions.decisions.map((decision) => (
                <tr key={decision.id}>
                  <td className="small">{formatTimestamp(decision.createdAt)}</td>
                  <td className="small">
                    <Link href={`${base}/policies/decisions/${decision.id}`}>
                      {decision.subjectLabel}
                    </Link>
                    <div className="muted">{decision.subjectKind.toLowerCase()}</div>
                  </td>
                  <td className="small mono">{decision.action}</td>
                  <td className="small">
                    {decision.resourceType}
                    <div className="muted">{decision.resourceSensitivity.toLowerCase()}</div>
                  </td>
                  <td>
                    <span className={`badge ${EFFECT_BADGES[decision.verdict] ?? ''}`}>
                      {decision.verdict.replaceAll('_', ' ').toLowerCase()}
                    </span>
                  </td>
                  <td className="mono small">{decision.riskScore}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canManage ? (
        <details className="card" style={{ marginTop: '1.5rem' }}>
          <summary>
            <strong>Create a rule</strong>
          </summary>
          <p className="small muted">
            Conditions are a JSON object. Use a small priority number for rules that must be
            evaluated first, and remember that an ALLOW rule for a sensitive resource should also
            name the trust level and posture it requires.
          </p>
          <ActionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/policies/rules`}
            submitLabel="Create rule"
            successMessage="Rule created."
            resetOnSuccess
            fields={[
              { name: 'name', label: 'Name', required: true, placeholder: 'Contractors need MFA' },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                full: true,
              },
              {
                name: 'priority',
                label: 'Priority',
                type: 'number',
                defaultValue: '100',
                help: 'Lower numbers are evaluated first.',
              },
              {
                name: 'effect',
                label: 'Effect',
                type: 'select',
                required: true,
                defaultValue: 'ALLOW',
                options: POLICY_EFFECTS.map((effect) => ({
                  value: effect,
                  label: effect.replaceAll('_', ' ').toLowerCase(),
                })),
              },
              {
                name: 'enabled',
                label: 'Enabled',
                type: 'checkbox',
                defaultValue: 'true',
              },
              {
                name: 'conditions',
                label: 'Conditions',
                type: 'json',
                required: true,
                full: true,
                defaultValue:
                  '{\n  "deviceTrustAtLeast": "PARTIAL",\n  "postureFresh": true,\n  "mfaSatisfied": true,\n  "zoneIn": ["CORPORATE"]\n}',
                help: `Available keys include roleIn, deviceTrustAtLeast, postureFresh, postureCheckPassed, mfaSatisfied, zoneIn (${ZONES.join(', ')}), sensitivityAtLeast, riskAtLeast and actionIn.`,
              },
            ]}
          />
        </details>
      ) : null}
    </>
  );
}
