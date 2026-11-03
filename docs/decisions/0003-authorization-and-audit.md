# ADR 0003: Capability authorization, tenant scoping, and tamper-evident audit

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Every Phase 1 workflow touches organization-owned records: assets, findings, incidents, notes, members, and audit history. The platform must deny by default, must not let one organization reach another organization's rows through identifiers, and must leave a reviewable record of privileged actions that cannot be silently rewritten through the application's own database role. UI-only enforcement and per-handler checks were rejected because they are easy to omit.

## Decision

### One capability policy

- Four organization roles exist: `OWNER`, `ADMIN`, `ANALYST`, `VIEWER`. A single module, `src/server/authz/roles.ts`, maps each role to explicit capabilities (`asset.create`, `finding.import`, `audit.read`, and so on) and is the only place a role is interpreted.
- Unknown or unexpected roles fail closed, and any capability that is not listed for a role is denied. Roles are not hierarchical at runtime: each role carries its own explicit capability set, and member management additionally refuses to let a non-owner grant or revoke `ADMIN` or `OWNER` memberships.
- Mutating capabilities are declared explicitly so that the second-factor rule and the audit action set can be derived from the same list.

### Tenant context resolved from membership, never from the request body

- `requireTenantContext` resolves the organization from the path parameter, requires an `ACTIVE` membership for the authenticated user, checks the capability, and enforces the second-factor rule for privileged roles. It returns a context object carrying the organization, membership, role, and user.
- Handlers never trust a client-supplied organization ID, and services re-scope every query by `ctx.organization.id`. Every child record is read with `{ id, organizationId }` so a guessed identifier from another tenant resolves to "not found" rather than being returned.
- Relationship inputs (assignee, incident, asset, member) are validated against the same organization before use.

### Uniform route wrappers

- API routes are wrapped by `withApi` or `withTenantApi`, which apply request metadata (request ID, IP, user agent), a same-origin check for every non-safe method, rate limiting, authentication, the capability check, and one error-mapping function. A route cannot forget an authorization step without changing the wrapper call.

### Tamper-evident audit trail

- Security-relevant actions append an event with actor, action, outcome, target, summary, metadata, IP, user agent, request ID, and timestamp.
- Each event is written inside the same transaction as the mutation it records, so a failed audit write rolls the mutation back.
- Events are chained per organization: a monotonic `sequence`, the previous event's hash, and a SHA-256 hash over a canonical serialization of the event. Writers take a per-organization PostgreSQL advisory transaction lock before reading the previous event, so concurrent writers cannot fork the chain.
- A PostgreSQL trigger rejects `UPDATE` and `DELETE` on `audit_events` with SQLSTATE `42501`, so ordinary application code and SQL cannot rewrite history. `verifyAuditChain` recomputes the chain and reports the first sequence that breaks.
- Access denials are audited as `access.denied` events when the request can be attributed to a tenant.

## Consequences

- Adding a capability requires updating the policy module, the audit action set where relevant, and the tests that assert role boundaries.
- The audit chain detects modification of committed events, but it is not a signature scheme: an actor with direct database superuser rights could rewrite the whole chain. Trust in the chain therefore rests on restricting database credentials and exporting events off-box before that authority is used.
- `TRUNCATE` is not blocked by the row-level trigger; it is used only by the test harness against the dedicated test database.
- Rate limiting uses a shared PostgreSQL fixed-window counter (`api_rate_limits`), so limits hold across instances without introducing Redis. The cost is one extra write per API request.
- Audit metadata must stay free of credentials, tokens, and unnecessary personal data. Event payloads are limited by construction to identifiers, statuses, counts, and titles, and every new action is reviewed with that rule in mind.
