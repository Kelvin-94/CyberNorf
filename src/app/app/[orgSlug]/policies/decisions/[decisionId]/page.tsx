import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { AppError } from '@/server/errors';
import { getPolicyDecision } from '@/server/services/policy';
import { loadTenantContext } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Decision · CyberNorf' };
export const dynamic = 'force-dynamic';

const EFFECT_BADGES: Record<string, string> = {
  ALLOW: 'success',
  DENY: 'critical',
  STEP_UP: 'medium',
  QUARANTINE: 'high',
};

export default async function PolicyDecisionPage({
  params,
}: {
  params: Promise<{ orgSlug: string; decisionId: string }>;
}) {
  const { orgSlug, decisionId } = await params;
  const ctx = await loadTenantContext(orgSlug, 'policy.read');
  if (!ctx) {
    notFound();
  }

  let decision;
  try {
    decision = await getPolicyDecision(ctx.organization.id, decisionId);
  } catch (error) {
    if (error instanceof AppError && error.statusCode === 404) {
      notFound();
    }
    throw error;
  }
  const base = `/app/${ctx.organization.slug}`;
  const explanation = decision.explanation;
  const summary = typeof explanation['summary'] === 'string' ? explanation['summary'] : null;
  const steps = Array.isArray(explanation['steps'])
    ? (explanation['steps'] as Array<Record<string, unknown>>)
    : [];
  const riskFactors = Array.isArray(explanation['riskFactors'])
    ? (explanation['riskFactors'] as Array<Record<string, unknown>>)
    : [];
  const obligations = Array.isArray(explanation['obligations'])
    ? (explanation['obligations'] as unknown[]).filter(
        (entry): entry is string => typeof entry === 'string',
      )
    : [];

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/policies/decisions`}>Decision log</Link>
          </p>
          <h1>{decision.subjectLabel}</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            {new Date(decision.createdAt).toLocaleString()} · risk {decision.riskScore} ·
            correlation <span className="mono">{decision.correlationId}</span>
          </p>
        </div>
        <span className={`badge ${EFFECT_BADGES[decision.verdict] ?? ''}`}>
          {decision.verdict.replaceAll('_', ' ').toLowerCase()}
        </span>
      </div>

      {summary ? (
        <div className="note" style={{ marginBottom: '1.25rem' }}>
          <p className="small" style={{ margin: 0 }}>
            {summary}
          </p>
        </div>
      ) : null}

      <section className="card">
        <h2>Request</h2>
        <dl className="detail-grid">
          <div>
            <dt>Subject</dt>
            <dd>
              {decision.subjectKind.toLowerCase()} ·{' '}
              <span className="mono">{decision.subjectId}</span>
            </dd>
          </div>
          <div>
            <dt>Action</dt>
            <dd className="mono">{decision.action}</dd>
          </div>
          <div>
            <dt>Resource</dt>
            <dd>
              {decision.resourceType}
              {decision.resourceId ? ` · ${decision.resourceId}` : ''}
            </dd>
          </div>
          <div>
            <dt>Sensitivity</dt>
            <dd>{decision.resourceSensitivity.toLowerCase()}</dd>
          </div>
          <div>
            <dt>Matched rule</dt>
            <dd className="mono small">{decision.matchedRuleId ?? 'none (default)'}</dd>
          </div>
        </dl>
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Evaluation order</h2>
        {steps.length === 0 ? (
          <p className="small muted">No rule steps were recorded.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Rule</th>
                <th>Effect</th>
                <th>Matched</th>
                <th>Failed conditions</th>
              </tr>
            </thead>
            <tbody>
              {steps.map((step, index) => (
                <tr key={String(step['ruleId'] ?? index)}>
                  <td className="mono small">{String(step['priority'] ?? '')}</td>
                  <td className="small">{String(step['ruleName'] ?? '')}</td>
                  <td className="small">{String(step['effect'] ?? '').toLowerCase()}</td>
                  <td>
                    <span className={`badge ${step['matched'] ? 'success' : 'low'}`}>
                      {step['matched'] ? 'yes' : 'no'}
                    </span>
                  </td>
                  <td className="small mono muted">
                    {Array.isArray(step['failedConditions']) && step['failedConditions'].length > 0
                      ? (step['failedConditions'] as unknown[])
                          .filter((entry): entry is string => typeof entry === 'string')
                          .join(', ')
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Risk factors</h2>
        {riskFactors.length === 0 ? (
          <p className="small muted">No risk factors contributed to this decision.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Factor</th>
                <th>Weight</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {riskFactors.map((factor, index) => (
                <tr key={`${String(factor['code'] ?? index)}-${index}`}>
                  <td className="mono small">{String(factor['code'] ?? '')}</td>
                  <td className="mono small">{String(factor['weight'] ?? '')}</td>
                  <td className="small muted">{String(factor['detail'] ?? '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {obligations.length > 0 ? (
          <p className="small muted" style={{ marginBottom: 0 }}>
            Obligations: {obligations.join(', ')}
          </p>
        ) : null}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Facts at decision time</h2>
        <p className="small muted">
          Stored as the decision point read them. Re-evaluating the same request today may produce a
          different verdict; this snapshot is what the answer was based on.
        </p>
        <pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
          {JSON.stringify(decision.facts, null, 2)}
        </pre>
      </section>
    </>
  );
}
