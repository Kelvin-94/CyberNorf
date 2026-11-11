# CyberNorf Roadmap

This roadmap is a planning baseline, not a promise of delivery dates. Items are complete only when code, tests, documentation, and review support that status.

**How to read it:** each phase lists what is **delivered** (checked, with the evidence that justifies the check) and what **remains** (unchecked, with the specific gap instead of a vague restatement). A `_Partial:_` note on an unchecked item means part of it ships but the item does not meet its own description yet. Capabilities that were built but were missing from earlier revisions of this file have been added to the phase where they belong rather than given a phase of their own.

Last aligned against the codebase: 2026-11-11.

## Phase 0 — Define the product

**Delivered**

- [x] Select the application stack and document the decision. [ADR 0001](docs/decisions/0001-application-stack.md).
- [x] Decide on project license before accepting external contributions. AGPL-3.0-or-later, in [README.md](README.md#license).
- [x] Decide hosted, self-hosted, or hybrid deployment. Self-hosted, one host, one database, TLS at the proxy; [ADR 0004](docs/decisions/0004-production-deployment.md) and [DEPLOYMENT.md](docs/DEPLOYMENT.md). Hosted multi-tenant SaaS is explicitly not the target.
- [x] Review [the threat model](docs/THREAT_MODEL.md). Reviewed and extended for identity governance and machine credentials; the control-status rows distinguish enforced, partial and absent.
- [x] Choose initial supported integrations. OIDC for identity in, signed outbound webhooks for events out; SIEM, SOAR, ticketing, chat apps and gateway/EDR connectors are deferred with reasons and reopening criteria in [ADR 0007](docs/decisions/0007-initial-integrations.md).
- [x] Write a data inventory and data-flow diagram. [DATA_INVENTORY.md](docs/DATA_INVENTORY.md) lists every table and file location with contents, sensitivity and lifecycle, the ten data flows, the trust boundaries, retention/deletion behaviour and the backup relationship between database and evidence volume.

**Remaining**

- [ ] Choose initial customer segment and main problem to solve. _Working assumption:_ small defensive security teams without a SOC platform, with the problem and the evidence that would falsify it recorded in [ADR 0006](docs/decisions/0006-initial-customer-segment.md). Status is **Proposed**: a document cannot validate a market, so the item stays unchecked until design-partner feedback exists.

**Exit criteria:** a narrow MVP scope, identified trust boundaries, and an agreed implementation plan.

## Phase 1 — Secure application foundation

**Delivered**

- [x] Authentication, MFA for privileged users, and secure session handling. Password sign-in with a 12-character minimum, eight-hour sliding sessions, TOTP with backup codes, and an optional single OpenID Connect provider (`src/server/auth/`).
- [x] Organization membership and role/capability model. Four roles with deny-by-default capabilities (`src/server/authz/`).
- [x] Non-human identity inventory, scoped machine credentials, and membership access reviews. _Implemented:_ identities of every kind carry an owner, criticality, lifecycle status and append-only timeline; machines start pending approval, are approved only by an owner, and receive one scoped, expiring, hash-stored bearer credential that only works on `/api/v1/identity/me`; access-review campaigns snapshot memberships and finalize retain/revoke decisions atomically (see [docs/IDENTITY_GOVERNANCE.md](docs/IDENTITY_GOVERNANCE.md)). Directory import, scheduled reviews and machine-credential recertification are not implemented.
- [x] Central policy enforcement on server-side operations. Every tenant route and server-rendered page resolves a `TenantContext` and checks capabilities; navigation only reflects them.
- [x] Tenant ownership checks and negative authorization tests. `tests/tenant-isolation.test.ts` plus per-module denial cases.
- [x] Personal API keys for automation. Scoped, expiring, hash-stored keys with their own authorization path (`src/server/authz/api-key.ts`, `/api/v1/me/api-keys`).
- [x] Audit events for authentication, permission changes, and privileged operations. Membership changes, data mutations, and access denials are hash-chained per organization; sign-in success and failure, second-factor verification, session ending, and two-factor disablement are recorded in the append-only `auth_events` table and shown to the account on `/account/security`.
- [x] CI checks for formatting, tests, dependency vulnerabilities, and secret leaks. `.github/workflows/ci.yml` runs `npm audit --audit-level=low`, format, lint, typecheck, migrations against a real PostgreSQL, the full test suite, a production build, a runtime audit against a live server, and a gitleaks history scan.
- [x] Structured logs with sensitive-value redaction. One JSON object per line on stdout with stable fields (`time`, `level`, `msg`, `service`, `env`), a `LOG_LEVEL` threshold, and child loggers for request-scoped fields (`src/server/logging/logger.ts`). Every record passes through the same redactor the audit trail uses before it is written, and logging never throws into the request it describes. Unhandled failures emit `request.unhandled_error` with the `requestId`; startup emits `server.started` with feature booleans only. Documented in [docs/LOGGING.md](docs/LOGGING.md) and covered by `logger.test.ts` and `errors.test.ts`. Access logs remain at the proxy so requests are not logged twice.

**Remaining**

- [ ] Secrets handling and safe configuration management. _Partial:_ every variable is validated at startup and by `npm run config:check`, which reports all problems at once, never prints values, and refuses a security-control downgrade. Secrets can be mounted as files through `SECRETS_DIR` (allow-listed variables, file-wins-over-environment, group/world-readable files refused) so Docker, Kubernetes and Vault-agent deliveries work without baking values into the environment. `npm run secrets:rotate` generates a replacement atomically with mode `0600`, refuses to overwrite without `--force`, never prints the value, and prints the rotation drill steps; `docs/SECRETS.md` carries the per-secret consequences (including that rotating `BETTER_AUTH_SECRET` logs everyone out and makes TOTP secrets unreadable). The effective configuration is fingerprinted at startup with an HMAC keyed by `BETTER_AUTH_SECRET` and stored in `system_settings`; a change is logged as `config.changed` and included in `server.started`. Remaining: no secrets-manager API client, rotation is assisted rather than scheduled, no rotation has been drilled against a real deployment, and the fingerprint records *that* the configuration changed and when, not what changed or who did it.

**Exit criteria:** sensitive routes have tested deny-by-default behavior; credentials are not committed to source; access boundaries are documented.

Status: exit criteria met for the implemented routes; secrets handling remains partial (see above), and structured logs now cover application faults and startup, not per-request access.

## Phase 2 — Defensive MVP

Build one complete, useful workflow rather than a wide collection of unfinished screens. Every item in this phase is delivered: the case workflow, detection input, alert delivery, evidence, indicators and export form an end-to-end path. Threat-intelligence enrichment is the notable remaining capability, and it belongs with the Phase 4 work rather than here.

**Delivered**

- [x] SOC case and incident workflow. Incident records with ownership, severity, notes, links to findings, and a forward-only lifecycle, every change audited (`INCIDENT_*` events). Evidence is attached through the evidence item below; promotion of an alert into a case is still absent.
- [x] Finding severity, rationale, and remediation tracking. Every finding carries a derived 0–100 risk score and a severity-based remediation deadline; the list filters and sorts on both; the dashboard reports overdue work, SLA compliance and mean time to resolve ([docs/FINDINGS.md](docs/FINDINGS.md)).
- [x] Audit history for important case changes. Incident and finding mutations append hash-chained events in the same transaction as the change.
- [x] Search constrained by authorization. Tenant-scoped, case-insensitive search over assets, findings, incidents and advisories, always composed with the caller's organization filter.
- [x] Endpoint monitoring and vulnerability intelligence. Agent enrollment with a one-time token and owner approval, signed runs (optional enforcement), heartbeat health, installed-package inventory, an imported advisory feed, and package-to-advisory matching that raises alerts.
- [x] Alert delivery with integrity. Notification channels with sealed signing secrets, HMAC-signed webhook transport, delivery records, and a cron-driven sweep with bounded retries.
- [x] Compliance and control evidence. Framework and control catalog, organization adoption, per-control attestation, evidence linked to real findings/incidents/assets, and agent checks mapped to controls.
- [x] Dashboards and reporting. Risk, SLA, agent health, and coverage summaries scoped to the organization.
- [x] Alert and IOC records with provenance. Indicators support domains, URLs, IPv4/IPv6, emails and MD5/SHA-256, stored normalised per tenant so repeated feed lines refresh one row instead of duplicating the observation history. Provenance covers source kind/name/URL/reference, first and last seen, confidence, expiry, actor and an append-only audit event; links attach an indicator to exactly one finding or incident with an `OBSERVED`/`REFERENCED` relation, are tenant-checked before write, and are covered by `tests/indicators.test.ts`. Enrichment is still absent and remains a later item.
- [x] Evidence attachment and integrity metadata. Files upload to `EVIDENCE_DIR` with a generated blob key (never a client-controlled path), are hashed while being written, size-limited mid-stream, and recorded with content type, size, SHA-256 and capture time. Verification re-reads the blob and reports `INTACT`/`MISMATCH`/`MISSING`, updates the row and appends an audit event; `npm run evidence:verify` sweeps a tenant or the whole database, and deletion removes the blob while refusing to strip the last evidence from an implemented control (`tests/evidence-files.test.ts`).
- [x] Search and export constrained by authorization. Search ships; export ships as `GET /api/v1/organizations/[orgSlug]/export`, gated by the `export.download` capability (owners, admins and analysts; not viewers), rate limited to five requests per five minutes, `Cache-Control: private, no-store`, and audited as `export.downloaded`. It carries business records, identity metadata without hashes, indicators and links, access reviews, quotas and the audit chain with its hashes; `EXPORT_VERSION` is 2 and credential fields are excluded. Covered by `tests/retention-export.test.ts`.
- [x] Unit and integration tests for expected and denied actions. 343 tests, all passing, including negative authorization and cross-tenant cases (`npm test`, 2026-11-11).

**Exit criteria:** a user can complete the chosen defensive workflow end-to-end, with authorization, audit, and documentation tested.

## Phase 3 — Operations and resilience

**Delivered**

- [x] Backup and restoration drills. `npm run db:restore-drill` dumps, restores, diffs tables/columns/constraints/triggers/migrations, re-verifies every audit chain with the application's own verifier, proves the append-only triggers still reject writes, and writes a JSON report. Documented in [DEPLOYMENT.md](docs/DEPLOYMENT.md#operating-it). A drill has to be run and its report retained to count as evidence.
- [x] Retention and deletion workflows. `data:retention` (dry-run first, audited purge) and `data:export`, both tested.
- [x] Deployment and rollback documentation. [DEPLOYMENT.md](docs/DEPLOYMENT.md), including upgrade and rollback behaviour for forward-only migrations.
- [x] Rate limits. Per-IP and per-user limits shared through PostgreSQL, with `Retry-After` and per-route budgets (`tests/rate-limit.test.ts`).
- [x] Liveness and readiness probes. `/api/health` never touches the database; `/api/ready` checks the database and compares applied migrations with the ones shipped in the image, answering `503` when the schema is behind the code.
- [x] Dependency vulnerability response, automated half. Dependabot with a cooldown and grouped development updates, plus `npm audit --audit-level=low` in CI and a gitleaks history scan.
- [x] Monitoring, alerting, and incident-response playbook. [INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) lists the detection sources with their exit codes and schedules (`/api/health` and `/api/ready` from outside the host, `evidence:verify`, `db:restore-drill`, audit verification, `config:check`, the `server.started`/`config.changed` startup lines, delivery records and capacity), the three-layer routing model, severity levels, and playbooks for host loss, database failure, evidence mismatch, secret compromise, authorization defects, delivery failure, account compromise and disk exhaustion. The product still ships no pager and no host-death notification: the external probe that supplies both is documented as a deployment requirement, and the gap is recorded.
- [x] Dependency update and vulnerability response process. [DEPENDENCY_RESPONSE.md](docs/DEPENDENCY_RESPONSE.md) adds the triage SLA (24 hours to decide and 72 hours to patch a critical), the decision record with `Patch`/`Mitigate`/`Accept`/`Not affected` values and mandatory review dates, the emergency patch procedure (including the full verification sequence), the customer advisory timings and content rules, and the monthly review. The known gaps are explicit: no SBOM, no automated base-image updates, and no advisory sent yet.

**Remaining**

- [ ] Resource quotas. _Partial:_ per-tenant row quotas for assets, findings, incidents, identities, agents, indicators and API keys, plus evidence-storage megabytes, are enforced inside the create transaction from tier defaults with `organization_quotas` overrides (`src/server/services/quotas.ts`). Operators get `GET .../quotas` and an audited `npm run quota` CLI (`show`, `set --apply`) that writes `quota.override_changed`. Remaining: findings created inside an agent run are deliberately not quota-checked so a limit cannot fail a whole run, and concurrent agent jobs are not bounded; job-level limits belong with the Phase 4 worker isolation.
- [ ] Security review of API and tenant isolation. _Partial:_ [SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) records the internal pass over all 62 tenant route files (89 handlers under `/api/v1/organizations/[orgSlug]`), all wrapped by `withTenantApi`: 30 `GET`s of which 29 bind to a `.read` capability and one is the deliberate `export.download` exception, and every write method bound to a mutating capability. The pass found and fixed one real misbinding — evidence verification was a database write and audit event behind `compliance.read`, now `compliance.evidence` — and the earlier latent `dispatchEventById` trap is gone, replaced by `dispatchEventForOrganization(organizationId, eventId)`. Tenant resolution still comes from membership, writes by primary key still follow a scoped fetch, and there are no server actions or page-level database access. What keeps this open is independence: the reviewer is the author, so an external review with write access to a seeded two-tenant environment is still required, and the brief for it is in the same document.

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

**Delivered**

- [x] Data residency for the shipped deployment model. The platform is self-hosted on the operator's host with a local database, so data residency is controlled by the operator and there are no subprocessors in the data path. Recorded in [DEPLOYMENT.md](docs/DEPLOYMENT.md). A hosted offering would reopen this.

**Remaining**

- [ ] SSO and enterprise identity integration. _Partial:_ one OpenID Connect provider can be configured, with PKCE and verified-email linking; no SAML, SCIM, directory sync, or automatic de-provisioning.
- [ ] Administrative access reviews. _Partial:_ manual membership recertification with per-item retain/revoke decisions and atomic revocation exists; scheduling, reviewer assignment/separation of duties, privileged-access campaigns, and non-human credential reviews remain open.
- [ ] Customer-configurable retention. _Partial:_ retention is a global operator-run script with `--days`; tenants cannot set their own policy, and the console cannot preview or trigger a purge.
- [ ] Documented data residency and subprocessors. _Partial:_ correct for the self-hosted model; required again before any managed or multi-region offering.
- [ ] Audit and evidence exports. _Partial:_ per-organization JSON export with a verifiable chain exists; there is no signed, portable evidence package for an external auditor.
- [ ] Independent security assessment.
- [ ] Availability and recovery targets based on tested capacity. There is one host and no measured RTO/RPO; the restore drill provides a method, not a target.
- [ ] Legal and privacy review for launch jurisdictions and target customers.

**Exit criteria:** product claims match verified controls, documented limitations, and actual operational capacity.

## Alignment notes

Changes made when this file was reconciled with the codebase, so the diff is explainable:

- **Added to Phase 0:** the deployment-model and threat-model-review items, both already decided.
- **Added to Phase 1:** personal API keys, which shipped with authentication but were never listed.
- **Added to Phase 2:** endpoint monitoring and advisory matching, alert delivery, compliance and control evidence, dashboards, and search. These were built and documented elsewhere but had no roadmap line, which made the roadmap understate the product.
- **Marked delivered in Phase 2:** the incident workflow, audit history for case changes, and the test item, all previously unchecked despite being implemented.
- **Added to Phase 3:** rate limits, liveness/readiness probes, and the automated half of dependency response.
- **Marked delivered in Phase 3:** retention, deployment documentation, and backup/restore drills (this one is backed by an executed drill and its JSON report).
- **Kept unchecked on purpose:** every item whose gap is named in a `_Partial:_` note. Partial work is not completion, and the exit criteria depend on the whole item.
- **Delivered after alignment:** structured application logs in Phase 1 — `src/server/logging/`, `docs/LOGGING.md`, `LOG_LEVEL` in `.env.example` and the environment tables, and two test files. While writing it, three documentation claims were corrected against the code: the CI dependency audit level is `low`, the compose healthcheck probes `/api/ready` rather than `/api/health`, and export then existed only as a script. Export has since gained the authorized API route described under Phase 2.
- **API and tenant-isolation review (Phase 3, still partial):** re-run with the same mechanical method after the indicator, evidence, quota and export routes landed. It parsed 62 tenant route files and 89 handlers, flagged every write bound to a `.read` capability and every `GET` not bound to one, and found one misbinding — the evidence-verification `POST` — which was fixed to `compliance.evidence`; the export `GET` is the single intentional exception and is documented as such. The earlier `dispatchEventById` latent trap was removed in the same work by replacing it with `dispatchEventForOrganization(organizationId, eventId)`. The reviewer is still the author, which is why the item is unchecked; the method, numbers and external-review brief are in [SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).
- **Secrets handling (Phase 1, still partial):** mounted secret files (`SECRETS_DIR`), the assisted rotation command with an atomic `0600` write and a refusal to overwrite, and the keyed configuration fingerprint recorded in `system_settings` and logged as `config.changed` all landed, with `docs/SECRETS.md` rewritten to match (it had listed all three as missing). The item stays unchecked for the reasons named there: no secrets-manager client, rotation is not scheduled, no drill has been run against a real deployment, and the fingerprint does not record what changed or who changed it.
- **Phase 0 decisions recorded:** [ADR 0006](docs/decisions/0006-initial-customer-segment.md) states the segment and problem as **Proposed** with the evidence that would falsify it — it deliberately does not close the item — and [ADR 0007](docs/decisions/0007-initial-integrations.md) closes the integration choice by deferring SIEM, SOAR, ticketing, chat and gateway connectors with reasons. [DATA_INVENTORY.md](docs/DATA_INVENTORY.md) closes the data-inventory item.
- **Phase 3 operations documents:** [INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md), [DEPENDENCY_RESPONSE.md](docs/DEPENDENCY_RESPONSE.md) and [SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md). Two items closed (monitoring/playbook, dependency process); quotas and the security review stay unchecked for the gaps named in their notes.
- **Verification for this revision:** `npm test` 343/343 passing, `npm run lint` clean, `npm run typecheck` clean, `npm run build` succeeded (2026-11-11).

## Release discipline

For each release:

1. Define scope and known limitations.
2. Review security-sensitive changes.
3. Run automated tests and relevant manual checks.
4. Confirm no secrets or sensitive data are included.
5. Publish installation, configuration, upgrade, and rollback instructions.
6. Record unresolved risks and follow-up owners.

Do not label the platform production-ready or compliant with a framework merely because a roadmap item or documentation file exists.
