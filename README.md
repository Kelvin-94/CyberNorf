# CyberNorf

**CyberNorf is a work-in-progress cybersecurity platform focused on defensive security, security operations, vulnerability management, and controlled security testing.**

> **Project status:** Early-stage, not production-ready. Phase 1 provides an authenticated, tenant-isolated SOC foundation (assets, findings, incidents, audit) with automated tests. Everything else in this README is a plan unless the [development status](#development-status) section says otherwise. Do not rely on it to protect production systems until the remaining phases are implemented and independently reviewed.

## Vision

Build a trustworthy workspace that helps individuals and security teams investigate alerts, organize evidence, prioritize vulnerabilities, document remediation, and conduct authorized assessments with clear scope and accountability.

CyberNorf is intended to put **authorization, least privilege, privacy, and auditability** at the center of the product—not treat them as afterthoughts.

## Planned capabilities

The following is a proposed roadmap, not a claim that these features exist today. Asset inventory, finding lifecycle and remediation tracking, role-based access, and auditable actions exist in the Phase 1 foundation described under [development status](#development-status); everything else remains planned.

- **SOC workflows:** case management, alert triage, investigation timelines, and evidence-linked reports.
- **Threat intelligence:** IOC organization, enrichment workflows, and links between observations and investigations.
- **Vulnerability management:** asset inventory, finding prioritization, remediation tracking, and safe verification workflows.
- **Security research workspace:** controlled static analysis and defensive investigation of suspicious files.
- **Authorized assessment management:** engagement records, approved target scope, exclusions, time windows, and emergency contacts.
- **Governance and audit:** role-based access, policy decisions, auditable actions, and evidence export.
- **Reporting:** clear findings, severity rationale, limitations, and actionable remediation recommendations.

## Core design principles

1. **Default deny:** sensitive actions are denied unless the required permission, scope, and approval checks pass.
2. **Least privilege:** users and services receive only the access they need.
3. **Authorization before testing:** active testing must be explicitly authorized and restricted to approved assets and time windows.
4. **Defense in depth:** enforce controls on the server and execution environment, not only in the UI.
5. **Privacy by design:** minimize collected data, isolate tenants, protect secrets, and define retention and deletion behavior.
6. **Accountability:** record security-relevant actions while protecting audit records from unauthorized alteration.
7. **Honest status:** document what is implemented, tested, planned, and known to be incomplete.

## Intended users

The initial focus is defensive security practitioners, SOC analysts, developers, and small security teams. More sensitive workflows should only be introduced after the authorization, isolation, logging, and incident-response controls are built and tested.

## Proposed architecture

The implementation may evolve, but the target separation is:

- **Web application:** user experience and workflow presentation.
- **API/backend:** authentication, business logic, validation, and authorization enforcement.
- **Policy layer:** role, capability, target scope, approval, and risk checks for sensitive actions.
- **Worker execution layer:** isolated jobs with limited network access, runtime limits, and cancellation controls.
- **Data layer:** tenant-aware persistence, secrets management, and controlled retention.
- **Audit and monitoring:** security events, administrative actions, alerts, and reviewable evidence.

Do not execute untrusted files or active security tests on the application host. Use isolated workers designed for the relevant threat model.

## Development status

**Phase 0 (product definition) and Phase 1 (secure SOC foundation) are implemented.** The application supports real multi-tenant workflows behind authenticated sessions, capability-based authorization, and a hash-chained audit trail. Phase 2 and later work described in the [roadmap](ROADMAP.md) is not implemented.

### What works today

- **Accounts:** email and password registration and sign-in (12-character minimum passwords), optional OpenID Connect single sign-on, eight-hour sliding sessions, sign-out, and TOTP enrollment with ten backup codes at `/account/security`.
- **Organizations:** create an organization, switch between organizations you belong to, and manage members and roles.
- **Assets:** register, edit, retire, and inspect organization-owned assets with type, identifier, criticality, and lifecycle status.
- **Findings:** create findings manually or import them as JSON, deduplicate by fingerprint, move them through the documented lifecycle, assign them, and record remediation.
- **Incidents:** create investigations, record notes, link findings, and move them through a forward-only lifecycle.
- **Audit:** every security-relevant action is written to a per-organization hash chain that the UI and API can verify.

### Security properties currently enforced

- Server-side deny-by-default capability checks on every tenant API route and every server-rendered tenant page; navigation only *reflects* those capabilities.
- Organization scope resolved from membership, never from client input. Records from another organization resolve to `404`, not `403`.
- TOTP second factor required for `OWNER` and `ADMIN` accounts before they can modify tenant data.
- Same-origin check for state changes, per-IP and per-user rate limits shared through PostgreSQL, bounded JSON bodies, and uniform error responses without stack traces.
- `UPDATE` and `DELETE` on audit rows rejected by a database trigger, with per-organization advisory locking so concurrent writers cannot fork the hash chain.

### Checks

```sh
npm test        # unit + database-backed integration tests (needs the test database)
npm run lint
npm run typecheck
npm run build
```

See [the local development guide](docs/DEVELOPMENT.md) for setup, test-database creation, and the demo walkthrough, [the production deployment guide](docs/DEPLOYMENT.md) for the TLS proxy and compose stack, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the implemented design.

### Known limitations

- No password reset, email verification, or invitation email. An owner or administrator must add an already-registered account by email.
- SSO is a single OpenID Connect provider enabled through `OIDC_*` variables: no SAML, no SCIM, and no automatic de-provisioning when someone leaves the identity provider.
- No file uploads or evidence attachments.
- No background worker is bundled: a cron job or systemd timer calls the alert sweep, and the retention and export scripts are run by an operator.
- The audit chain is hash-linked but not signed, and depends on restricting direct database access.
- Rate-limit counters are only removed when `data:retention` runs with `--prune-rate-limits`.
- Retention never removes findings, incidents, assets, compliance evidence, or audit rows; a person closes those records.
- The production stack targets one host: one console container against one PostgreSQL database, with no horizontal scaling or high availability.

Before any public or production release, still required: backup and restoration drills, monitoring and alerting, retention and deletion workflows, deployment and rollback documentation, and an independent security review.

## Security reporting

Please do not publish live credentials, personal data, or sensitive exploit details in public issues. See [SECURITY.md](SECURITY.md) for the current reporting guidance.

## Contributing

Contribution guidance will evolve with the codebase. Begin with [CONTRIBUTING.md](CONTRIBUTING.md). Do not submit secrets, real customer data, malware samples, or changes that enable unauthorized activity.

## License

CyberNorf is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**. See [LICENSE](LICENSE) for the full license text.

The AGPL is a copyleft license intended for software that may be offered as a network service: if you modify the covered program and let users interact with that modified version over a network, the license includes obligations to offer those users the corresponding source code. It does not prohibit commercial use or paid hosting.

This license applies to CyberNorf code covered by the project copyright. Third-party dependencies, assets, and contributions may have their own license terms; review them before redistribution. This is a project licensing choice, not legal advice.

## Disclaimer

CyberNorf is intended for lawful defensive security and explicitly authorized testing. Users are responsible for obtaining permission before testing systems and for complying with applicable laws, contracts, and policies.
