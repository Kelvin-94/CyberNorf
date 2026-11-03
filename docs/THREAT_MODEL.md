# CyberNorf — Initial Threat Model

**Status:** Initial working document. Revisit this model whenever data flows, integrations, capabilities, or deployment boundaries change. The threat table below lists requirements to validate, not claims that implementation is complete; the [control status](#control-status-for-the-phase-1-foundation) section records what the current code actually enforces.

## Scope

This model covers the planned web application, API, identity and authorization services, tenant data, uploaded artifacts, background jobs, integrations, and audit pipeline.

## Security objectives

- Prevent unauthorized access to customer data and security capabilities.
- Prevent one tenant from reading or modifying another tenant's resources.
- Prevent active testing outside an approved target scope.
- Prevent untrusted files and tool output from compromising the platform.
- Protect credentials, sensitive investigation data, and audit records.
- Preserve integrity and availability of evidence and case histories.
- Make policy decisions and privileged actions attributable and reviewable.

## Assets to protect

1. User credentials, sessions, API tokens, signing keys, and integration secrets.
2. Customer assets, incident records, vulnerability findings, and uploaded artifacts.
3. Engagement authorizations, target allowlists, exclusions, and approval records.
4. Worker infrastructure, queue messages, and privileged service identities.
5. Audit events and security evidence.
6. Platform configuration, deployment pipeline, backups, and release artifacts.

## Trust boundaries

- Browser to API.
- User and organization to another tenant.
- Application services to worker execution environments.
- Platform to third-party integrations and external intelligence feeds.
- Uploaded or imported content to trusted application logic.
- Operators and administrators to customer data.
- Source repository and build pipeline to deployed production artifacts.

## Threat scenarios and required mitigations

| Threat | Potential impact | Required mitigation and verification |
|---|---|---|
| Broken object-level authorization | A user reads or changes another organization's case or finding | Check ownership on every request; add negative cross-tenant tests for read, update, delete, export, and search paths |
| Privilege escalation | A standard user invokes an administrator or restricted security action | Central server-side authorization, explicit capabilities, deny-by-default policy, and role-boundary tests |
| Out-of-scope testing | A job targets an unapproved third-party asset | Require explicit scope and time window; validate on dispatch and execution; deny redirects or resolved targets outside policy; test edge cases |
| Malicious uploaded file | Worker or host compromise, data leakage, resource exhaustion | Quarantine, size/type limits, isolated disposable workers, restricted egress, resource quotas, and cleanup tests |
| Prompt or content injection | Untrusted logs, advisories, or files influence AI/tool actions | Treat external content as data, not instructions; separate model recommendations from execution authority; require deterministic policy checks for sensitive operations |
| SSRF and unsafe URL fetching | Access to internal services or cloud metadata | Egress controls, block private/link-local ranges where appropriate, DNS rebinding safeguards, redirect revalidation, and allowlisted integrations |
| Secret leakage | Account takeover or unauthorized access | Secret manager, least-privilege tokens, secret scanning, redaction, rotation procedures, and incident playbook |
| Audit tampering or gaps | Loss of accountability or misleading evidence | Restricted write path, append-oriented storage, integrity checks, alert on logging failure, access reviews, and export verification |
| Dependency or build compromise | Malicious code enters a release | Dependency pinning and review, automated scanning, protected release process, provenance where feasible, and tested rollback |
| Denial of service or cost abuse | Platform degradation or unexpected infrastructure cost | Rate limits, queue quotas, bounded jobs, backpressure, quotas per tenant, and alerting |
| Sensitive-data over-retention | Privacy and compliance exposure | Data inventory, minimization, retention schedule, deletion tests, access logging, and documented legal exceptions |
| Administrator misuse | Unauthorized inspection or export of customer data | Separate privileged roles, just-in-time access where practical, approvals for exceptional access, and audit review |

## Abuse cases to test

- User A changes a record ID and attempts to access User B's or another tenant's data.
- A revoked user continues to use an old session or worker token.
- An engagement expires while a job is queued or running.
- A target redirects to an address outside the approved range.
- DNS answers change between validation and connection.
- A file has a misleading extension, extreme size, or malformed content.
- A worker attempts to reach internal control-plane endpoints.
- The audit store is unavailable during a sensitive action.
- An imported report contains instructions designed to trigger unauthorized tool use.
- A user attempts to export data beyond their organization or permission set.

## Control status for the Phase 1 foundation

The table above lists requirements. This table records which of them the current code actually enforces, and what remains open. See [ARCHITECTURE.md](ARCHITECTURE.md) for the implemented design and [ADR 0002](decisions/0002-identity-and-sessions.md) and [ADR 0003](decisions/0003-authorization-and-audit.md) for the reasoning.

| Threat | Current state |
|---|---|
| Broken object-level authorization | Implemented for all current routes: tenant scope is derived from an active membership and every query is re-scoped; cross-tenant reads, writes, and relationship abuse are covered by `tests/tenant-isolation.test.ts` and `tests/findings-workflow.test.ts`. |
| Privilege escalation | Implemented: single capability matrix, deny-by-default, unknown roles denied, second factor required for `OWNER`/`ADMIN` mutations, and only owners may grant or revoke administrator roles. Role-boundary tests exist in `src/server/authz/roles.test.ts` and `tests/tenant-isolation.test.ts`. |
| Out-of-scope testing | Not applicable yet: no execution or scanning capability exists. Required before Phase 4. |
| Malicious uploaded file | Not applicable yet: no upload or execution surface exists. Body size and content-type limits exist for JSON. |
| Prompt or content injection | Not applicable yet: no model-driven actions. |
| SSRF and unsafe URL fetching | Not applicable yet: the server fetches no user-supplied URLs. |
| Secret leakage | Partial: secrets come from the environment, production rejects an auth secret shorter than 32 characters, error responses never include stack traces, and CI runs gitleaks plus `npm audit`. No secrets manager, redaction pipeline, or rotation procedure yet. |
| Audit tampering or gaps | Implemented for what is recorded: transactional appends, per-organization advisory lock, SHA-256 chain, database trigger blocking `UPDATE`/`DELETE`, and a verification endpoint. Not yet recorded: authentication events. No off-box export, so a database superuser could still rewrite the chain. |
| Dependency or build compromise | Partial: lockfile, `npm ci`, high-severity audit gate, and secret scanning in CI. No dependency update policy, release provenance, or protected release process. |
| Denial of service or cost abuse | Partial: shared fixed-window rate limits on API routes and on Better Auth endpoints, bounded request bodies, and paginated queries. No per-tenant quotas or alerting. |
| Sensitive-data over-retention | Open: no retention policy, export, or deletion workflow. Tenant deletion relies on database cascades. |
| Administrator misuse | Partial: role separation and a reviewable audit trail exist; no just-in-time access, approval workflow, or access reviews. |

## Risk treatment principles

- Prefer prevention and containment over relying on detection alone.
- Deny sensitive actions when scope, approval, or policy evaluation is unavailable.
- Keep defensive analysis available without granting unrestricted active-testing permissions.
- Use synthetic data and lab targets for development and automated tests.
- Make emergency suspension and session/job revocation available to authorized operators.
- Document residual risks and owners rather than silently accepting them.

## Open questions

- Will CyberNorf execute any security tools, or initially orchestrate external tools only?
- Will it accept malware samples, and under what storage and execution policy?
- Will the first release be single-tenant or multi-tenant?
- What customer data is collected, where is it processed, and for how long?
- Which roles may access customer content for support or incident response?

Resolve these questions before production deployment. This document is not a certification, audit, or guarantee of security.
