# CyberNorf Roadmap

This roadmap is a planning baseline, not a promise of delivery dates. Items are complete only when code, tests, documentation, and review support that status.

## Phase 0 — Define the product

- [ ] Choose initial customer segment and main problem to solve.
- [ ] Decide hosted, self-hosted, or hybrid deployment.
- [ ] Choose initial supported integrations.
- [ ] Write a data inventory and data-flow diagram.
- [ ] Review [the threat model](docs/THREAT_MODEL.md).
- [x] Select the application stack and document the decision.
- [x] Decide on project license before accepting external contributions.

**Exit criteria:** a narrow MVP scope, identified trust boundaries, and an agreed implementation plan.

## Phase 1 — Secure application foundation

- [x] Authentication, MFA for privileged users, and secure session handling.
- [x] Organization membership and role/capability model.
- [x] Central policy enforcement on server-side operations.
- [x] Tenant ownership checks and negative authorization tests.
- [ ] Secrets handling and safe configuration management. _Partial:_ secrets come from the environment, production refuses a weak auth secret, and repository secret scanning is in CI, but there is no secrets manager, rotation procedure, or startup validation for every variable.
- [ ] Structured logs with sensitive-value redaction. _Not started:_ audit events are the security record; application logging is limited to request-correlated error messages.
- [x] Audit events for authentication, permission changes, and privileged operations. Membership changes, data mutations, and access denials are hash-chained per organization; sign-in success and failure, second-factor verification, session ending, and two-factor disablement are recorded in the append-only `auth_events` table and shown to the account on `/account/security`.
- [x] CI checks for formatting, tests, dependency vulnerabilities, and secret leaks.

**Exit criteria:** sensitive routes have tested deny-by-default behavior; credentials are not committed to source; access boundaries are documented.

Status: met for the implemented routes, except secrets handling (still partial) and structured application logs (not started).

## Phase 2 — Defensive MVP

Build one complete, useful workflow rather than a wide collection of unfinished screens. Phase 1 already delivers incident records with notes, finding severity and remediation tracking, and audited case changes; Phase 2 extends these workflows with provenance, evidence, search, and export.

- [ ] SOC case and incident workflow.
- [ ] Alert and IOC records with provenance.
- [ ] Evidence attachment and integrity metadata.
- [x] Finding severity, rationale, and remediation tracking. _Implemented:_ every finding carries a derived risk score and a severity-based remediation deadline, the list filters and sorts on both, and the dashboard reports overdue work, SLA compliance, and mean time to resolve (see [docs/FINDINGS.md](docs/FINDINGS.md)).
- [ ] Search and export constrained by authorization.
- [ ] Audit history for important case changes.
- [ ] Unit and integration tests for expected and denied actions.

**Exit criteria:** a user can complete the chosen defensive workflow end-to-end, with authorization, audit, and documentation tested.

## Phase 3 — Operations and resilience

- [ ] Backup and restoration drills.
- [ ] Monitoring, alerting, and incident-response playbook.
- [ ] Retention and deletion workflows.
- [ ] Rate limits and resource quotas.
- [ ] Dependency update and vulnerability response process.
- [ ] Deployment and rollback documentation.
- [ ] Security review of API and tenant isolation.

**Exit criteria:** the team can detect important failures, recover data, and revoke compromised access.

## Phase 4 — Controlled execution and authorized testing

Do not begin this phase until the prior security foundation is implemented and reviewed.

- [ ] Explicit engagement and target-scope model.
- [ ] Authorization records, exclusions, approval, and expiry.
- [ ] Isolated workers with restricted network egress.
- [ ] Resource limits, job cancellation, and cleanup.
- [ ] Scope enforcement at job dispatch and execution time.
- [ ] Tests for redirects, DNS changes, expired scope, and cancellation.
- [ ] Human review for higher-risk capabilities.

**Exit criteria:** out-of-scope execution is denied and verified by repeatable tests. Never use production or third-party systems as test targets without explicit authorization.

## Phase 5 — Enterprise readiness

- [ ] SSO and enterprise identity integration.
- [ ] Administrative access reviews.
- [ ] Customer-configurable retention where appropriate.
- [ ] Documented data residency and subprocessors.
- [ ] Audit and evidence exports.
- [ ] Independent security assessment.
- [ ] Availability and recovery targets based on tested capacity.
- [ ] Legal and privacy review for launch jurisdictions and target customers.

**Exit criteria:** product claims match verified controls, documented limitations, and actual operational capacity.

## Release discipline

For each release:

1. Define scope and known limitations.
2. Review security-sensitive changes.
3. Run automated tests and relevant manual checks.
4. Confirm no secrets or sensitive data are included.
5. Publish installation, configuration, upgrade, and rollback instructions.
6. Record unresolved risks and follow-up owners.

Do not label the platform production-ready or compliant with a framework merely because a roadmap item or documentation file exists.
