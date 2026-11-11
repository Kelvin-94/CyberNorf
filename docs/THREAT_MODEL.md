# CyberNorf — Initial Threat Model

**Status:** Initial working document. Revisit this model whenever data flows, integrations, capabilities, or deployment boundaries change. The threat table below lists requirements to validate, not claims that implementation is complete; the [control status](#control-status-for-the-phase-1-foundation) section records what the current code actually enforces.

## Scope

This model covers the planned web application, API, identity and authorization services, identity-governance records and machine credentials, tenant data, uploaded artifacts, background jobs, integrations, and audit pipeline. The identity-governance slice is analyzed in more detail in [IDENTITY_GOVERNANCE.md](IDENTITY_GOVERNANCE.md).

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
7. The identity inventory, its ownership map, and non-human credentials, including access-review decisions that attest to who still needs access.

## Trust boundaries

- Browser to API.
- User and organization to another tenant.
- Application services to worker execution environments.
- Platform to third-party integrations and external intelligence feeds.
- Uploaded or imported content to trusted application logic.
- Operators and administrators to customer data.
- Source repository and build pipeline to deployed production artifacts.

## Threat scenarios and required mitigations

| Threat                               | Potential impact                                                                                                            | Required mitigation and verification                                                                                                                                                         |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Broken object-level authorization    | A user reads or changes another organization's case or finding                                                              | Check ownership on every request; add negative cross-tenant tests for read, update, delete, export, and search paths                                                                         |
| Privilege escalation                 | A standard user invokes an administrator or restricted security action                                                      | Central server-side authorization, explicit capabilities, deny-by-default policy, and role-boundary tests                                                                                    |
| Out-of-scope testing                 | A job targets an unapproved third-party asset                                                                               | Require explicit scope and time window; validate on dispatch and execution; deny redirects or resolved targets outside policy; test edge cases                                               |
| Malicious uploaded file              | Worker or host compromise, data leakage, resource exhaustion                                                                | Quarantine, size/type limits, isolated disposable workers, restricted egress, resource quotas, and cleanup tests                                                                             |
| Prompt or content injection          | Untrusted logs, advisories, or files influence AI/tool actions                                                              | Treat external content as data, not instructions; separate model recommendations from execution authority; require deterministic policy checks for sensitive operations                      |
| SSRF and unsafe URL fetching         | Access to internal services or cloud metadata                                                                               | Egress controls, block private/link-local ranges where appropriate, DNS rebinding safeguards, redirect revalidation, and allowlisted integrations                                            |
| Secret leakage                       | Account takeover or unauthorized access                                                                                     | Secret manager, least-privilege tokens, secret scanning, redaction, rotation procedures, and incident playbook                                                                               |
| Audit tampering or gaps              | Loss of accountability or misleading evidence                                                                               | Restricted write path, append-oriented storage, integrity checks, alert on logging failure, access reviews, and export verification                                                          |
| Dependency or build compromise       | Malicious code enters a release                                                                                             | Dependency pinning and review, automated scanning, protected release process, provenance where feasible, and tested rollback                                                                 |
| Denial of service or cost abuse      | Platform degradation or unexpected infrastructure cost                                                                      | Rate limits, queue quotas, bounded jobs, backpressure, quotas per tenant, and alerting                                                                                                       |
| Sensitive-data over-retention        | Privacy and compliance exposure                                                                                             | Data inventory, minimization, retention schedule, deletion tests, access logging, and documented legal exceptions                                                                            |
| Administrator misuse                 | Unauthorized inspection or export of customer data                                                                          | Separate privileged roles, just-in-time access where practical, approvals for exceptional access, and audit review                                                                           |
| Stale or orphaned non-human identity | A forgotten service account keeps working after its owner or workload is gone; nobody notices because no human logs into it | Mandatory owner at registration, `UNOWNED_MACHINE` and pending-approval risk signals, mandatory credential expiry, last-used tracking, and an owner-only approval gate                       |
| Machine credential theft or replay   | A copied bearer token reads tenant identity data until it expires or is revoked                                             | Single narrow scope, short TTL, hash-only storage, one active credential per identity, per-credential rate limit, uniform `401` failures, and immediate revocation on rotation or suspension |
| Access-review evasion                | A reviewer retains their own access or an unreviewed item is silently skipped                                               | Per-item decisions by a manager/owner, all items required before finalization, last-owner protection, and an atomic audit record of every revocation                                         |

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
- A machine presents a revoked, expired, or out-of-scope credential to `/api/v1/identity/me`.
- A machine credential is used to call a tenant route or to read another identity.
- An analyst approves a machine identity, or a non-owner approves one.
- A review is finalized with an item still pending, or with the only active owner marked for revocation.
- A membership is revoked while the person still holds a live session.

## Control status for the Phase 1 foundation

The table above lists requirements. This table records which of them the current code actually enforces, and what remains open. See [ARCHITECTURE.md](ARCHITECTURE.md) for the implemented design, [IDENTITY_GOVERNANCE.md](IDENTITY_GOVERNANCE.md) for the identity slice, and [ADR 0002](decisions/0002-identity-and-sessions.md), [ADR 0003](decisions/0003-authorization-and-audit.md) and [ADR 0005](decisions/0005-identity-governance.md) for the reasoning.

| Threat                               | Current state                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Broken object-level authorization    | Implemented for all current routes: tenant scope is derived from an active membership and every query is re-scoped; cross-tenant reads, writes, and relationship abuse are covered by `tests/tenant-isolation.test.ts` and `tests/findings-workflow.test.ts`.                                                                                                                                                                                                                                                                                                                                    |
| Privilege escalation                 | Implemented: single capability matrix, deny-by-default, unknown roles denied, second factor required for `OWNER`/`ADMIN` mutations, and only owners may grant or revoke administrator roles. Role-boundary tests exist in `src/server/authz/roles.test.ts` and `tests/tenant-isolation.test.ts`.                                                                                                                                                                                                                                                                                                 |
| Out-of-scope testing                 | Not applicable yet: no execution or scanning capability exists. Required before Phase 4.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Malicious uploaded file              | Not applicable yet: no upload or execution surface exists. Body size and content-type limits exist for JSON.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Prompt or content injection          | Not applicable yet: no model-driven actions.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| SSRF and unsafe URL fetching         | Implemented for webhook delivery: targets are resolved and private/link-local addresses refused unless explicitly allowed for development, the validated address is pinned for the actual request, redirects are not followed, and delivery is time-bounded (`src/server/security/outbound.ts`, `webhook-transport.ts`).                                                                                                                                                                                                                                                                         |
| Secret leakage                       | Implemented within the application: secrets come from the environment, production rejects an auth secret shorter than 32 characters, agent tokens and personal API keys are stored only as hashes, webhook signing keys are sealed with AES-256-GCM, error responses never include stack traces, and every log line, audit summary, and audit metadata value passes through credential redaction before it is written or hashed (`src/server/security/redaction.ts`). CI runs gitleaks plus `npm audit`. A dedicated secrets manager and a documented rotation drill are still operational gaps. |
| Audit tampering or gaps              | Implemented for what is recorded: transactional appends, per-organization advisory lock, SHA-256 chain, database trigger blocking `UPDATE`/`DELETE`, and a verification endpoint. Not yet recorded: authentication events. No off-box export, so a database superuser could still rewrite the chain.                                                                                                                                                                                                                                                                                             |
| Dependency or build compromise       | Partial: lockfile, `npm ci`, high-severity audit gate, and secret scanning in CI. No dependency update policy, release provenance, or protected release process.                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Denial of service or cost abuse      | Partial: shared fixed-window rate limits on API routes and on Better Auth endpoints, bounded request bodies, and paginated queries. No per-tenant quotas or alerting.                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Sensitive-data over-retention        | Open: no retention policy, export, or deletion workflow. Tenant deletion relies on database cascades.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Administrator misuse                 | Partial: role separation and a reviewable audit trail exist, and membership access reviews now record retain/revoke decisions with atomic finalization. Still open: just-in-time access, approval for exceptional data access, and scheduled or privileged-access reviews.                                                                                                                                                                                                                                                                                                                       |
| Stale or orphaned non-human identity | Implemented for the governed records: machine registration requires an owner, approval is owner-only, lifecycle transitions are a closed table, and the risk heuristic surfaces pending approval, unowned machines, missing or expired credentials, and credentials expiring within 30 days. Not solved: nothing imports the directory, so a service account that was never registered is still invisible.                                                                                                                                                                                       |
| Machine credential theft or replay   | Implemented within the bearer-token model: SHA-256 storage, one active credential per identity, single scope `identity.self.read`, mandatory expiry, per-IP and per-credential rate limits, uniform `401` failures, and revocation on rotation, suspension, deprovision or scope narrowing. Residual: a stolen token can be replayed until expiry; there is no mTLS, workload attestation, IP allowlist, or per-request nonce.                                                                                                                                                                   |
| Access-review evasion                | Implemented for membership reviews: every item must be decided, decisions and reviewer are recorded per item, the last active `OWNER` cannot be revoked, and revoked memberships are disabled with their sessions deleted in the same transaction as the audit event. Self-review is blocked per item, but any `OWNER` or `ADMIN` can decide another member's item and there is no reviewer assignment or separation-of-duties rule. Reviews are manual and cannot be reopened, and machine credentials are out of scope.                                                                        |

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
