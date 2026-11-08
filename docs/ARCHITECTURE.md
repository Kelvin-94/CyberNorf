# CyberNorf — Initial Architecture

**Status:** Mixed. The [implemented Phase 1 foundation](#implemented-phase-1-foundation) section describes code that exists and is covered by automated tests. Everything after it describes the target design for later phases and is not implemented.

## Goals

- Build a defensive-security platform with auditable workflows.
- Keep identity, authorization, execution, and data-access responsibilities separate.
- Make sensitive actions fail closed when required context or approvals are missing.
- Make it possible to test and reason about security boundaries independently.

## Implemented Phase 1 foundation

### Code map

| Area                                                          | Location                                                     |
| ------------------------------------------------------------- | ------------------------------------------------------------ |
| Identity provider (Better Auth) and auth HTTP surface         | `src/lib/auth.ts`, `src/app/api/auth/[...all]/route.ts`      |
| Browser auth client                                           | `src/lib/auth-client.ts`, `src/lib/api-client.ts`            |
| Server-rendered session helpers                               | `src/server/ui/session.ts`                                   |
| Capability policy                                             | `src/server/authz/roles.ts`                                  |
| Tenant context and second-factor gate                         | `src/server/authz/context.ts`                                |
| Route wrappers (metadata, CSRF, rate limit, authz, errors)    | `src/server/api/handler.ts`                                  |
| Error model                                                   | `src/server/errors.ts`                                       |
| Request metadata, same-origin check, bounded JSON body parser | `src/server/http/request-meta.ts`                            |
| Audit append, hash chain, verifier                            | `src/server/audit/audit.ts`, `src/server/audit/canonical.ts` |
| Domain services                                               | `src/server/services/*.ts`                                   |
| Input validation                                              | `src/server/validation/*.ts`                                 |
| Workflow state machines                                       | `src/server/domain/transitions.ts`                           |
| Agent domain rules (tokens, scopes, lifecycle)                 | `src/server/domain/agents.ts`                                |
| Agent bearer-token route wrapper                              | `src/server/api/agent.ts`                                    |
| Builtin offline host monitor                                 | `scripts/agent/monitor.mjs`                                  |
| UI routes and components                                      | `src/app/**`, `src/components/**`                            |
| Tests                                                         | `tests/*.test.ts`, `src/**/*.test.ts`                        |

### Request lifecycle

Every tenant API route is created with `withTenantApi(capability, options, handler)`:

1. Build request metadata: correlation ID (validated `X-Request-Id` or a UUID), client address from `X-Forwarded-For`/`X-Real-IP`, truncated user agent.
2. For any non-safe method, reject cross-site requests: `Sec-Fetch-Site: cross-site` and an `Origin` outside `BETTER_AUTH_URL` produce `403`.
3. Consume a fixed-window rate-limit entry in PostgreSQL. Defaults are 240 read requests and 60 writes per minute per client address; import, member management, organization creation, and audit verification have tighter per-user budgets.
4. Resolve the session from the cookie through Better Auth. Missing or expired sessions produce `401`.
5. Resolve the organization from the path slug, require an `ACTIVE` membership, verify the capability for this route, and require a TOTP second factor for privileged roles on mutating capabilities. Denials produce `403` (`FORBIDDEN` or `MFA_REQUIRED`) and append an `access.denied` audit event.
6. Parse a bounded JSON body (`415` for the wrong content type, `413` above 256 KB, or 1 MB for the bulk import endpoint) and validate it with Zod (`422` with field details). At most 500 findings may be imported per request.
7. Call the domain service, which re-scopes every query by the resolved organization ID and writes the mutation plus its audit event in one transaction.
8. Serialize with `Cache-Control: no-store`, `X-Request-Id`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. Errors use one shape: `{ "error": { "code", "message", "requestId" } }`, with no stack traces or internal identifiers.

Server-rendered pages use the same authorization primitives: `requireSessionUser` and `loadTenantContext` run on the server before any tenant data is read, and a denied capability renders an access-denied view instead of partial data.

### Data model

All tenant rows carry `organizationId` and are only reachable through a resolved membership.

| Model                                                                  | Purpose and notable constraints                                                                                                                                                                                                                |
| ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `User`, `Session`, `Account`, `Verification`, `TwoFactor`, `RateLimit` | Better Auth identity tables, generated by the library.                                                                                                                                                                                         |
| `Organization`                                                         | Tenant root. `slug` is unique and restricted to lowercase hostname-safe characters. `tier` is recorded but gates no capability in v1.                                                                                                          |
| `Membership`                                                           | `role` (`OWNER`, `ADMIN`, `ANALYST`, `VIEWER`) and `status` (`ACTIVE`, `DISABLED`), unique per user and organization. Removal is a soft disable.                                                                                               |
| `Asset`                                                                | Organization-owned inventory: type, identifier, criticality, lifecycle status, and `verificationStatus`. Identifier is unique per organization. `verificationStatus` records an operator declaration only; no DNS or IAM proof is implemented. |
| `Finding`                                                              | Vulnerability or observation with severity, status, source (`MANUAL`, `IMPORT`, or `AGENT`), a fingerprint unique per organization used for deduplication, optional CVE, CVSS score, asset, assignee, incident, optional `agentId` provenance, and remediation text. |
| `Incident`                                                             | Investigation record with severity, status, detection and closure timestamps, assignee, and linked findings.                                                                                                                                   |
| `IncidentNote`                                                         | Append-only-by-convention investigation notes with author and body.                                                                                                                                                                            |
| `Framework`, `FrameworkControl`                                        | Global read-only catalog of compliance frameworks and their controls. Seeded by migration, identical for every tenant, and ordered by an explicit `position` so the list reads like the standard.                                              |
| `OrganizationFramework`                                                | One tenant's adoption of a catalog framework, unique per organization and framework, with adoption date, adopting user, and an optional target audit date.                                                                                     |
| `OrganizationControl`                                                  | Per-tenant attestation of one catalog control: status, owner, notes, review dates, and who last updated it. Unique per adoption and control. A CHECK constraint requires `lastReviewedAt` whenever the status is `PARTIAL` or `IMPLEMENTED`.   |
| `ControlEvidence`                                                      | Audit-grade support for a control, pointing at exactly one finding, incident, asset, or external reference. A CHECK constraint enforces the single-target rule in the database as well as in validation.                                       |
| `Agent`                                                                | Scoped monitoring agent: source (`BUILTIN`, `OPENAI`, `ANTHROPIC`, `CUSTOM`, `OTHER`), status, granted scopes, SHA-256 `tokenHash` (unique), display prefix, expiry, approval and revocation stamps, and last-seen counters. Unique name per organization. |
| `AgentRun`                                                             | One submitted monitoring run: host, platform, timing, derived pass/fail/skip counts, linked findings, and the raw check array. Runs are immutable history; findings carry the operational state. |
| `AuditEvent`                                                           | Hash-chained, append-only security record (see below).                                                                                                                                                                                         |
| `ApiRateLimit`                                                         | Shared fixed-window counters for application routes.                                                                                                                                                                                           |

### Roles and capabilities

The matrix lives in `src/server/authz/roles.ts` and is the single source of truth.

| Capability                                                  | OWNER | ADMIN | ANALYST | VIEWER |
| ----------------------------------------------------------- | :---: | :---: | :-----: | :----: |
| `organization.read`                                         |  yes  |  yes  |   yes   |  yes   |
| `asset.read`, `finding.read`, `incident.read`, `audit.read` |  yes  |  yes  |   yes   |  yes   |
| `asset.create`, `asset.update`                              |  yes  |  yes  |   yes   |   no   |
| `finding.create`, `finding.update`, `finding.import`        |  yes  |  yes  |   yes   |   no   |
| `incident.create`, `incident.update`, `incident.note`       |  yes  |  yes  |   yes   |   no   |
| `asset.delete`, `finding.delete`, `incident.delete`         |  yes  |  yes  |   no    |   no   |
| `compliance.read`                                           |  yes  |  yes  |   yes   |  yes   |
| `compliance.evidence`                                       |  yes  |  yes  |   yes   |   no   |
| `compliance.manage`                                         |  yes  |  yes  |   no    |   no   |
| `agent.read`                                                |  yes  |  yes  |   yes   |  yes   |
| `agent.manage`                                              |  yes  |  yes  |   no    |   no   |
| `organization.update`, `organization.manage_members`        |  yes  |  yes  |   no    |   no   |

`OWNER` and `ADMIN` must have a TOTP second factor enrolled before any mutating capability succeeds. Unknown roles and unlisted capabilities are denied.

`agent.manage` admits administrators to registration, but approval, suspension, resumption, and revocation are additionally restricted to `OWNER` inside the service, because they issue or destroy a credential.

### Workflow state machines

- Findings: the main path is `OPEN → TRIAGED → IN_PROGRESS → RESOLVED`, with `ACCEPTED_RISK` and `FALSE_POSITIVE` as further closure states. An `IN_PROGRESS` finding can be sent back to `TRIAGED`, and any closed finding can be reopened to `OPEN` or `TRIAGED`. Only transitions in the table in `src/server/domain/transitions.ts` are accepted; anything else returns `409 CONFLICT`. `resolvedAt` is set only when a finding becomes `RESOLVED`.
- Incidents: `OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`, with a documented path back from `CONTAINED` to `INVESTIGATING`, from `RESOLVED`/`CLOSED` to `OPEN`, and from `OPEN` straight to `CONTAINED` or `CLOSED`. Resolution and closure timestamps are recorded on those transitions.

### Compliance posture

Frameworks are adopted per tenant; adoption creates one attestation row per catalog control at `NOT_STARTED`. The score is weighted, not a green-row count (`src/server/domain/compliance.ts`):

- Credit per control: `IMPLEMENTED` 1, `PARTIAL` 0.5, `IN_PROGRESS` 0.25, `NOT_STARTED` 0.
- `NOT_APPLICABLE` leaves the denominator instead of counting as a pass, so marking everything inapplicable cannot manufacture a high score.
- Score is `credited weight / applicable weight`, one decimal, and is banded `READY` (>=90), `PROGRESSING` (>=60), `AT_RISK`, or `NOT_ASSESSED` when nothing applicable remains.
- A control can only move to `IMPLEMENTED` with at least one piece of evidence attached; the mutation returns `409 CONFLICT` otherwise. Moving into `PARTIAL` or `IMPLEMENTED` stamps `lastReviewedAt`.
- Evidence must belong to the same tenant. Cross-tenant identifiers resolve as `404`, the same as an unknown id.
- The last piece of evidence of an `IMPLEMENTED` control cannot be deleted until the status steps back, and a framework cannot be withdrawn while any evidence is attached. Both rules keep the audit record from disappearing behind a status change.
- Attested controls with no evidence (for example after the referenced finding was deleted) are surfaced as integrity warnings rather than silently lowering the score.

The bundled catalog is a curated subset of each standard (SOC 2, ISO/IEC 27001, NIST CSF 2.0, PCI DSS, GDPR) and explicitly not the complete control text; the UI and API label it as a tracking aid rather than a legal opinion or a certification.

### Monitoring agents

Agents collect host evidence and submit it to CyberNorf. The platform never calls a model provider, so monitoring keeps working on a network with no outbound Internet access; the only network action is the agent's own request to your instance.

- Sources: `BUILTIN` (the bundled `scripts/agent/monitor.mjs`), `OPENAI`, `ANTHROPIC`, `CUSTOM`, and `OTHER`. The source is provenance, not trust: every source goes through the same scoped report endpoint.
- Approval: a `BUILTIN` agent is registered by an owner or administrator and starts `ACTIVE`, because the operator is installing it on a host the organization already owns. Every external source is created `PENDING_APPROVAL` with no token hash at all, and only an `OWNER` can approve it. Approval issues the credential and may narrow the requested scopes; it cannot widen them.
- Credentials: `cna_` plus 32 random bytes, base64url. Only the SHA-256 hash is stored, plus a six-character display prefix. Builtin tokens live 365 days and third-party tokens 90 days. The plaintext token is returned exactly once, from registration or approval, and cannot be recovered afterwards.
- Scopes: `monitor.report` submits runs, `monitor.read` reads the agent's own record and history. A request outside the granted set returns `403`. Agent routes are wrapped by `withAgentApi`, which reads only the `Authorization: Bearer` header, never a session cookie, and rate-limits 60 requests per minute per address before authentication and 120 per minute per agent afterwards.
- Lifecycle: `PENDING_APPROVAL → ACTIVE → SUSPENDED → ACTIVE`, with `REVOKED` reachable from every non-revoked state and terminal. Suspension keeps history but stops the credential; revocation clears the token hash as well as the status.
- Ingestion: the agent sends observations only. `POST /api/v1/agents/me/runs` derives the run status (every check skipped is `PARTIAL`, no checks at all is `FAILED`), the pass/fail/skip counts, and the findings. Each failed check creates or refreshes one finding keyed by a fingerprint over organization, check id, and target, attributed to the agent's registering operator with `source = AGENT` and `agentId` set. A finding a person already resolved, accepted as risk, or marked a false positive is not reopened by a later run; the run reports it as suppressed instead.
- History: runs are immutable; the console drills down from an agent to its runs and from a run to the checks and linked findings. Every registration, approval, suspension, resumption, revocation, and accepted run appends to the audit chain, with `actorType = AGENT` for runs.
- Offline operation: `monitor.mjs` has no dependencies beyond Node. It collects locally, can write a report with `--out` on an air-gapped host, and can submit a carried report with `--in` from a connected host. A check whose evidence is unreadable is reported `SKIP` rather than passed, so reduced coverage is visible instead of implied assurance.

### Audit trail

Appends are transactional with the mutation, have a per-organization advisory lock, and are chained with SHA-256 over a canonical serialization (`sequence`, previous hash, actor, action, outcome, target, summary, metadata, timestamp). A database trigger rejects `UPDATE` and `DELETE`. `GET /api/v1/organizations/:orgSlug/audit/verify` recomputes the chain and reports the first broken sequence; the audit page exposes the same check.

### UI surfaces

- Public: landing page, `sign-in`, `sign-up`, `two-factor` challenge.
- Account: `account/security` for TOTP enrollment and backup codes.
- Tenant workspace under `/app/:orgSlug`: dashboard, assets (list and detail), findings (list, detail, status control, JSON import), incidents (list, detail, notes, linked findings), compliance (posture overview, framework detail with attestations, control detail with evidence), agents (list, registration with one-time token reveal, detail with approval and lifecycle controls, run drill-down), audit (filters and chain verification), members, and settings.
- Navigation renders only capabilities the current membership holds, but enforcement always happens on the server.

### Known limitations of this phase

- No CSP or document-level security headers; the headers listed above apply to API responses.
- No password reset, email verification, or invitation email flow. People must register before an owner or administrator can add them.
- No file upload or export. Compliance evidence links to existing findings, incidents, and assets, or to an external reference string; documents are not stored.
- Rate-limit counters are not garbage collected.
- The audit chain is hash-linked but not signed.
- No background worker, execution layer, or integrations; every workflow is synchronous HTTP. Agents run on their own schedule (cron, `launchd`, Task Scheduler); the platform never initiates a scan.
- Agent tokens cannot be rotated in place. Rotation is revoke-and-register, which is why revocation is separate from suspension.
- The monitor's checks are a conservative baseline for Linux and macOS hosts; they are not a CIS benchmark, and no Windows-specific check is implemented.

## Target logical components (later phases)

```mermaid
flowchart TD
    U[User / Organization] --> W[Web Application]
    W --> A[API and Application Services]
    A --> I[Identity and Session Service]
    A --> P[Policy Enforcement Point]
    P --> D[Domain Services]
    D --> DB[(Tenant-aware Data Store)]
    D --> Q[Job Queue]
    Q --> G[Worker Gateway]
    G --> S[Isolated Workers]
    A --> AU[Audit Event Pipeline]
    P --> AU
    G --> AU
    AU --> AL[(Append-only Audit Store)]
    M[Monitoring and Alerting] --> AU
```

All boxes are target logical boundaries. They may be deployed differently, but their responsibilities should remain explicit.

## Component responsibilities

### Web application

- Present workflows and current permission state.
- Never be the sole enforcement point for authorization.
- Avoid placing secrets in browser storage or URLs.
- Treat user-submitted content and rendered analysis as untrusted.

### API and application services

- Authenticate every request that requires an identity.
- Validate inputs at trust boundaries.
- Invoke centralized authorization checks for sensitive operations.
- Apply rate limits, request-size limits, and safe error handling.
- Avoid exposing stack traces, internal identifiers, or secret-bearing payloads.

### Identity and sessions

- Support MFA for privileged accounts and stronger verification for high-risk access.
- Use secure session rotation and revocation.
- Enforce tenant membership and role changes server-side.
- Record important authentication and administrative events without logging credentials.

### Policy enforcement

For each sensitive action, evaluate the actor, organization, requested capability, target, engagement scope, time window, approval state, and contextual risk. Deny by default if a required check is missing or invalid.

Prefer short-lived, scoped authorization grants over permanent broad permissions. A granted profile is not universal permission to target arbitrary systems.

### Domain services

Keep SOC cases, indicators, findings, assets, engagements, and reports in separate modules with explicit ownership and access rules. Record provenance for imported intelligence and evidence.

### Job queue and isolated workers

- Never execute untrusted samples or active tests inside the API process.
- Use disposable workers or equivalent isolation appropriate to each workload.
- Restrict outbound network access by default.
- Apply CPU, memory, disk, process, and execution-time limits.
- Use narrowly scoped service credentials; do not pass the main application secret to workers.
- Validate target scope at dispatch and, where practical, again at execution.
- Support cancellation, worker teardown, and retention limits.
- Treat network allowlists as defense in depth, not proof of authorization.

### Data store and file handling

- Enforce tenant boundaries in service logic and, where supported, at the data layer.
- Encrypt data in transit and at rest.
- Keep secrets in a dedicated secrets manager or equivalent secure facility.
- Store file metadata and content separately where useful; use content hashing and size/type limits.
- Quarantine uploads and avoid trusting filenames or claimed content types.
- Define deletion and retention behavior before handling real customer data.

### Audit pipeline

Capture actor, organization, action, target reference, authorization decision, correlation ID, timestamp, and result for security-relevant events. Avoid retaining unnecessary sensitive payloads. Restrict modification and deletion of audit records, monitor audit-pipeline failures, and test export integrity.

## Authorization decision model

A sensitive request should proceed only when all required checks pass:

1. The user and session are valid.
2. The account and organization are active.
3. The role grants the requested capability.
4. The target is within an explicit approved scope, if applicable.
5. The authorization is current and has not been revoked.
6. Required approvals and safety checks are satisfied.
7. Resource limits and execution guardrails are in place.

UI hiding is not enforcement. API handlers and execution workers must apply server-side checks.

## Target domain model for later phases

The Phase 1 entities (`User`, `Organization`, `Membership`, `Asset`, `Finding`, `Incident`, `IncidentNote`, `AuditEvent`) and the compliance catalog and attestation entities (`Framework`, `FrameworkControl`, `OrganizationFramework`, `OrganizationControl`, `ControlEvidence`) exist with migrations. Later phases add:

- `Engagement`, `ScopeEntry`, `Approval` for authorized-assessment records;
- `Indicator`, `EvidenceArtifact` for threat intelligence and evidence;
- `Job`, `RetentionPolicy` for the execution layer and data lifecycle;
- `PolicyDecision` if decision logging grows beyond the current audit events.

Every organization-owned record should have an explicit ownership model. Avoid trusting client-supplied organization IDs; derive or validate them from the authenticated membership.

## Operational prerequisites

Before production use, document:

- supported deployment model and trust boundaries;
- backup, restoration, and disaster-recovery procedures;
- monitoring, incident handling, and credential rotation;
- dependency and container-image update process;
- data residency, subprocessors, retention, and deletion;
- security testing and release acceptance criteria.

## Architecture decisions still open

Accepted decisions:

- [ADR 0001](decisions/0001-application-stack.md) — v1 application stack.
- [ADR 0002](decisions/0002-identity-and-sessions.md) — identity, sessions, and second factors.
- [ADR 0003](decisions/0003-authorization-and-audit.md) — capability authorization, tenant scoping, and tamper-evident audit.

The following deployment and product decisions remain open:

- cloud-hosted, self-hosted, or hybrid deployment;
- single-tenant versus multi-tenant launch;
- required integrations and data volume;
- whether uploaded samples or security tools will execute in the platform;
- hosting, operating budget, and support expectations.

Record material choices and their trade-offs in architecture decision records as they are approved.
