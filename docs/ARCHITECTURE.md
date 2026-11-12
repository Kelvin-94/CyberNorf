# CyberNorf — Initial Architecture

**Status:** Mixed. The [implemented Phase 1 foundation](#implemented-phase-1-foundation) section describes code that exists and is covered by automated tests, including the identity-governance, scoped-execution and data-lifecycle work delivered after it. Sections that describe later phases or target design are not implemented; each remaining gap is listed under known limitations.

## Goals

- Build a defensive-security platform with auditable workflows.
- Keep identity, authorization, execution, and data-access responsibilities separate.
- Make sensitive actions fail closed when required context or approvals are missing.
- Make it possible to test and reason about security boundaries independently.

## Implemented Phase 1 foundation

### Code map

| Area                                                            | Location                                                                     |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Identity provider (Better Auth) and auth HTTP surface           | `src/lib/auth.ts`, `src/app/api/auth/[...all]/route.ts`                      |
| Optional OIDC single sign-on settings                           | `src/server/auth/oidc.ts`                                                    |
| Browser auth client                                             | `src/lib/auth-client.ts`, `src/lib/api-client.ts`                            |
| Server-rendered session helpers                                 | `src/server/ui/session.ts`                                                   |
| Capability policy                                               | `src/server/authz/roles.ts`                                                  |
| Tenant context and second-factor gate                           | `src/server/authz/context.ts`                                                |
| Route wrappers (metadata, CSRF, rate limit, authz, errors)      | `src/server/api/handler.ts`                                                  |
| Error model                                                     | `src/server/errors.ts`                                                       |
| Request metadata, same-origin check, bounded JSON body parser   | `src/server/http/request-meta.ts`                                            |
| Audit append, hash chain, verifier                              | `src/server/audit/audit.ts`, `src/server/audit/canonical.ts`                 |
| Domain services                                                 | `src/server/services/*.ts`                                                   |
| Input validation                                                | `src/server/validation/*.ts`                                                 |
| Workflow state machines                                         | `src/server/domain/transitions.ts`                                           |
| Agent domain rules (tokens, scopes, lifecycle)                  | `src/server/domain/agents.ts`                                                |
| Agent bearer-token route wrapper                                | `src/server/api/agent.ts`                                                    |
| Identity-governance domain rules (lifecycle, credentials, risk) | `src/server/domain/identity.ts`                                              |
| Identity inventory, credential and access-review services       | `src/server/services/identities.ts`, `src/server/services/access-reviews.ts` |
| Machine-identity bearer route wrapper                           | `src/server/api/identity.ts`                                                 |
| Execution scope engine, denial descriptions, redirect chain     | `src/server/domain/execution.ts`                                             |
| Engagement, authorization, worker and job services              | `src/server/services/engagements.ts`, `src/server/services/execution.ts`     |
| Signed evidence package build and verification                  | `src/server/services/evidence-package.ts`, `scripts/data/verify-evidence-package.ts` |
| Builtin offline host monitor                                    | `scripts/agent/monitor.mjs`                                                  |
| UI routes and components                                        | `src/app/**`, `src/components/**`                                            |
| Tests                                                           | `tests/*.test.ts`, `src/**/*.test.ts`                                        |

### Request lifecycle

Every tenant API route is created with `withTenantApi(capability, options, handler)`:

1. Build request metadata: correlation ID (validated `X-Request-Id` or a UUID), client address from `X-Forwarded-For`/`X-Real-IP`, truncated user agent.
2. For any non-safe method, reject cross-site requests: `Sec-Fetch-Site: cross-site` and an `Origin` outside `BETTER_AUTH_URL` produce `403`. Requests that carry an `Authorization` header skip this check: a browser does not attach a bearer credential on its own, and a cross-site page cannot set the header without a CORS preflight.
3. Consume a fixed-window rate-limit entry in PostgreSQL. Defaults are 240 read requests and 60 writes per minute per client address; import, member management, organization creation, and audit verification have tighter per-user budgets. A bearer-authenticated request also consumes a key-scoped bucket, so one key cannot exhaust its owner's console budget and an address cannot hide behind a shared key.
4. Resolve the caller: an `Authorization: Bearer cnk_...` personal API key or the Better Auth session cookie. Missing, malformed, unknown, revoked, and expired credentials all produce the same `401`, and a bearer header that is present but unusable never falls back to the cookie.
5. Resolve the organization from the path slug, require an `ACTIVE` membership, verify the capability for this route, and require a TOTP second factor for privileged roles on mutating capabilities. A personal API key is bound to one organization and receives `404` for any other, including ones its owner belongs to. Denials produce `403` (`FORBIDDEN` or `MFA_REQUIRED`) and append an `access.denied` audit event.
6. Parse a bounded JSON body (`415` for the wrong content type, `413` above 256 KB, or 1 MB for the bulk import endpoint) and validate it with Zod (`422` with field details). At most 500 findings may be imported per request.
7. Call the domain service, which re-scopes every query by the resolved organization ID and writes the mutation plus its audit event in one transaction.
8. Serialize with `Cache-Control: no-store`, `X-Request-Id`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. Errors use one shape: `{ "error": { "code", "message", "requestId" } }`, with no stack traces or internal identifiers.

Server-rendered pages use the same authorization primitives: `requireSessionUser` and `loadTenantContext` run on the server before any tenant data is read, and a denied capability renders an access-denied view instead of partial data.

### Data model

All tenant rows carry `organizationId` and are only reachable through a resolved membership.

| Model                                                                  | Purpose and notable constraints                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `User`, `Session`, `Account`, `Verification`, `TwoFactor`, `RateLimit` | Better Auth identity tables, generated by the library.                                                                                                                                                                                                                                                                                                                                                                                  |
| `Organization`                                                         | Tenant root. `slug` is unique and restricted to lowercase hostname-safe characters. `tier` is recorded but gates no capability in v1.                                                                                                                                                                                                                                                                                                   |
| `Membership`                                                           | `role` (`OWNER`, `ADMIN`, `ANALYST`, `VIEWER`) and `status` (`ACTIVE`, `DISABLED`), unique per user and organization. Removal is a soft disable.                                                                                                                                                                                                                                                                                        |
| `Asset`                                                                | Organization-owned inventory: type, identifier, criticality, lifecycle status, and `verificationStatus`. Identifier is unique per organization. `verificationStatus` records an operator declaration only; no DNS or IAM proof is implemented.                                                                                                                                                                                          |
| `Finding`                                                              | Vulnerability or observation with severity, status, source (`MANUAL`, `IMPORT`, or `AGENT`), a fingerprint unique per organization used for deduplication, optional CVE, CVSS score, asset, assignee, incident, optional `agentId` provenance, and remediation text.                                                                                                                                                                    |
| `Incident`                                                             | Investigation record with severity, status, detection and closure timestamps, assignee, and linked findings.                                                                                                                                                                                                                                                                                                                            |
| `IncidentNote`                                                         | Append-only-by-convention investigation notes with author and body.                                                                                                                                                                                                                                                                                                                                                                     |
| `Framework`, `FrameworkControl`                                        | Global read-only catalog of compliance frameworks and their controls. Seeded by migration, identical for every tenant, and ordered by an explicit `position` so the list reads like the standard.                                                                                                                                                                                                                                       |
| `OrganizationFramework`                                                | One tenant's adoption of a catalog framework, unique per organization and framework, with adoption date, adopting user, and an optional target audit date.                                                                                                                                                                                                                                                                              |
| `OrganizationControl`                                                  | Per-tenant attestation of one catalog control: status, owner, notes, review dates, and who last updated it. Unique per adoption and control. A CHECK constraint requires `lastReviewedAt` whenever the status is `PARTIAL` or `IMPLEMENTED`.                                                                                                                                                                                            |
| `ControlEvidence`                                                      | Audit-grade support for a control, pointing at exactly one finding, incident, asset, or external reference. A CHECK constraint enforces the single-target rule in the database as well as in validation.                                                                                                                                                                                                                                |
| `Agent`                                                                | Scoped monitoring agent: source (`BUILTIN`, `OPENAI`, `ANTHROPIC`, `CUSTOM`, `OTHER`), status, granted scopes, SHA-256 `tokenHash` (unique), display prefix, expiry, approval and revocation stamps, last-seen counters, the operator's expected reporting interval, and the pending-outage marker. Unique name per organization.                                                                                                       |
| `AgentRun`                                                             | One submitted monitoring run: host, platform, timing, derived pass/fail/skip counts, linked findings, and the raw check array. Runs are immutable history; findings carry the operational state.                                                                                                                                                                                                                                        |
| `CheckControlMap`                                                      | Operator-declared link between a monitoring check id and one control of an adopted framework. Unique per organization, check and control. Mapped checks file their findings as control evidence automatically.                                                                                                                                                                                                                          |
| `NotificationChannel`                                                  | Tenant alert destination: HTTPS URL, AES-256-GCM sealed signing secret, enable flag, and last-delivery state. Unique name per organization.                                                                                                                                                                                                                                                                                             |
| `NotificationEvent`                                                    | Outbox row for one delivery: type (`AGENT_OFFLINE`, `AGENT_RECOVERED`, `TEST`), JSON payload, status, attempt counter, next-attempt time, delivery time, and last error. Unique `(channelId, dedupeKey)` so a repeated sweep cannot page twice.                                                                                                                                                                                         |
| `Advisory`                                                             | Tenant advisory feed entry: identifier (CVE, GHSA, or vendor id), package name, ecosystem (`BREW`, `NPM`, `PYPI`, `APT`, `RPM`), severity, affected version range in npm syntax, fixed version, CVSS score, reference URL, and publication date. Unique per organization, identifier, and package name.                                                                                                                                 |
| `SoftwareItem`                                                         | Last-known package on a host, reported by an agent: ecosystem, name, version, first and last seen timestamps, and the resolved asset. Unique per agent, ecosystem, and name, so a package disappears when a run stops reporting it.                                                                                                                                                                                                     |
| `UserApiKey`                                                           | Personal API credential for the console API: owner, single organization, SHA-256 `keyHash` (unique), six-character display prefix, required expiry, last-use timestamp, and revocation stamp. CHECK constraints enforce the digest shape and a prefix that cannot hold more than the six display characters.                                                                                                                            |
| `Identity`                                                             | Tenant identity inventory: `kind` (`HUMAN`, `MACHINE`), type, canonical lower-cased identifier unique per organization, criticality, lifecycle status, source, accountable owner, optional linked console user, approved machine scopes, credential TTL, and approval/suspension/deprovision stamps. A CHECK constraint keeps machine rows unlinked from users, and a canonical-identifier CHECK makes case-only duplicates impossible. |
| `IdentityCredential`                                                   | Scoped bearer credential for a non-human identity: SHA-256 `keyHash` (unique), six-character prefix, scopes, expiry, last use, and revocation stamp and reason. The plaintext is returned once at issue time and never stored.                                                                                                                                                                                                          |
| `IdentityEvent`                                                        | Object-level append-only identity timeline. A database trigger rejects `UPDATE` and `DELETE`, matching the audit chain's integrity rule.                                                                                                                                                                                                                                                                                                |
| `AccessReview`                                                         | Recertification campaign with `ACTIVE`/`COMPLETED`/`CANCELLED` status and a due date strictly after creation. There is no draft state.                                                                                                                                                                                                                                                                                                  |
| `AccessReviewItem`                                                     | Snapshot of one membership under review: member name, email and role at snapshot time, one `PENDING`/`RETAIN`/`REVOKE` decision, reviewer and timestamp. A CHECK constraint keeps an undecided item free of decision metadata and requires both reviewer and timestamp once decided.                                                                                                                                                    |
| `AuditEvent`                                                           | Hash-chained, append-only security record (see below).                                                                                                                                                                                                                                                                                                                                                                                  |
| `ApiRateLimit`                                                         | Shared fixed-window counters for application routes.                                                                                                                                                                                                                                                                                                                                                                                    |

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
| `notification.read`, `advisory.read`                        |  yes  |  yes  |   yes   |  yes   |
| `notification.manage`, `advisory.manage`                    |  yes  |  yes  |   no    |   no   |
| `identity.read`, `access_review.read`                       |  yes  |  yes  |   yes   |  yes   |
| `identity.manage`, `access_review.manage`                   |  yes  |  yes  |   no    |   no   |
| `organization.update`, `organization.manage_members`        |  yes  |  yes  |   no    |   no   |
| `member.manage_privileged`                             |  yes  |  no   |   no    |   no   |
| `engagement.authorize`                                     |  yes  |  no   |   no    |   no   |
| `agent.approve`                                            |  yes  |  no   |   no    |   no   |
| `identity.approve`                                         |  yes  |  no   |   no    |   no   |
| `retention.purge`                                          |  yes  |  no   |   no    |   no   |

`OWNER` and `ADMIN` must have a TOTP second factor enrolled before any mutating capability succeeds. Unknown roles and unlisted capabilities are denied.

`agent.manage` admits administrators to registration and configuration, but approval, suspension, resumption and revocation need the owner-only `agent.approve` capability, because they issue or destroy a credential.

`identity.manage` follows the same pattern: administrators and owners can register, edit, suspend, deprovision, and issue credentials, but approving a non-human identity for use needs the owner-only `identity.approve` capability. Machine credentials are opaque bearer tokens (`cnid_...`) verified only on `/api/v1/identity/me`; they never authenticate a console session. See [IDENTITY_GOVERNANCE.md](IDENTITY_GOVERNANCE.md) for the module design and threat model.

**Owner is the superuser tier.** An `OWNER` has every `ADMIN` capability plus exactly five owner-only decisions: `member.manage_privileged` (grant or revoke an `ADMIN` or `OWNER` membership), `engagement.authorize` (approve or revoke an authorization to test), `agent.approve` (approve, suspend, resume or revoke an agent), `identity.approve` (let a non-human identity authenticate) and `retention.purge` (destroy retained history). The set is exported as `OWNER_ONLY_CAPABILITIES` and a unit test fails if it changes silently. Owner is not a shortcut around the product: a second factor is still required, every decision is still audited, a requester still cannot approve their own authorization, and an owner still cannot read another tenant.

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
- Lifecycle: `PENDING_APPROVAL → ACTIVE → SUSPENDED → ACTIVE`, with `REVOKED` reachable from every non-revoked state and terminal. Suspension keeps history but stops the credential; revocation clears the token hash as well as the status. An active agent's credential can be rotated in place by an owner: the row, its runs and its check mappings are kept, only the hash, prefix and expiry change, and `agent.token_rotated` records both prefixes.
- Signed submissions: the monitor signs `x-cybernorf-timestamp` and `x-cybernorf-signature` (HMAC-SHA256 over `<seconds>.<raw body>`, key derived from the agent token). The runs route verifies against the raw bytes before parsing, rejects a timestamp outside five minutes, and always rejects a signature that arrives but does not verify. `AGENT_REQUIRE_SIGNED_RUNS=true` additionally refuses unsigned submissions, which also protects against a leaked token being used without the key derivation; rotation invalidates both at once.
- Ingestion: the agent sends observations only. `POST /api/v1/agents/me/runs` derives the run status (every check skipped is `PARTIAL`, no checks at all is `FAILED`), the pass/fail/skip counts, and the findings. Each failed check creates or refreshes one finding keyed by a fingerprint over organization, check id, and target, attributed to the agent's registering operator with `source = AGENT` and `agentId` set. A finding a person already resolved, accepted as risk, or marked a false positive is not reopened by a later run; the run reports it as suppressed instead.
- History: runs are immutable; the console drills down from an agent to its runs and from a run to the checks and linked findings. Every registration, approval, suspension, resumption, revocation, and accepted run appends to the audit chain, with `actorType = AGENT` for runs.
- Compliance: `CheckControlMap` links a check id to a control of a framework the tenant adopted. A failing mapped check files its finding as `ControlEvidence` (`kind = FINDING`) and audits `compliance.evidence_added` as an agent action, so technical telemetry becomes audit evidence without anyone copying it by hand. Attachments are idempotent per finding; unmapping stops future attachments and keeps what was already filed.
- Offline operation: `monitor.mjs` has no dependencies beyond Node. It collects locally, can write a report with `--out` on an air-gapped host, and can submit a carried report with `--in` from a connected host. A check whose evidence is unreadable is reported `SKIP` rather than passed, so reduced coverage is visible instead of implied assurance.
- Software inventory: a run may carry up to 800 packages (`inventory`). The server resolves the report hostname to a tenant asset, creating a `HOSTNAME` asset when the host is new, and replaces that agent's snapshot with the reported list, so an uninstalled package does not linger. Each package is then matched against the tenant's advisories of the same ecosystem: name comparison is case-insensitive, ecosystems never cross-match, and the range is evaluated by the comparator in `src/server/domain/versions.ts`. A match creates one finding per advisory and host (`<package> <version> is affected by <identifier>`, `source = AGENT`, `cveId` set only when the identifier is a CVE, remediation naming the fixed version). A repeat run refreshes that finding instead of duplicating it, and a finding a person closed is left alone. Importing an advisory does not scan retroactively; the next run of each agent performs the match.
- Heartbeats: an agent with an expected interval is `ONLINE`, `STALE`, or `OFFLINE` based on how many intervals have passed since its last run. `GET /api/cron/notifications` performs one bounded sweep and delivery pass, authenticated by a constant-time `CRON_SECRET` bearer check that fails closed with `503` when unconfigured. A host that stops reporting queues one alert per enabled destination, deduplicated per outage, and a host that reports again queues a recovery while dropping any outage alert that has not been sent yet. Delivery is a signed webhook (`x-cybernorf-signature` over timestamp and body) with five backoff attempts; attempts are claimed atomically so overlapping sweeps cannot double-send.

### Scoped execution control plane

Active testing is the only capability that acts on a system outside the platform, so it is stored, approved and evaluated as data rather than trusted to the caller (`src/server/domain/execution.ts`, `src/server/services/engagements.ts`, `src/server/services/execution.ts`).

- Engagements: one organization, a status (`DRAFT`, `ACTIVE`, `PAUSED`, `CLOSED`) and a `startsAt`/`endsAt` window. A job outside an active window is denied before any target is resolved.
- Scope: `INCLUDE` and `EXCLUDE` entries over `DOMAIN`, `IP_ADDRESS`, `CIDR` or `URL`, evaluated deny-by-default. A target must match an inclusion and no exclusion, and an exclusion wins over a broader inclusion. A `URL` rule pins scheme, host, port and a path prefix, so approving one path does not approve the whole host; a `DOMAIN` rule also covers its subdomains.
- Authorization: an `EngagementAuthorization` has its own window and must be `APPROVED`, with the requester and the approver as different people (`engagement.authorize`). Revocation takes effect on the next evaluation. The capabilities `engagement.read`, `engagement.manage` and `engagement.authorize` are separate, so an analyst can prepare scope without being able to authorize it.
- Two enforcement points, not one. Dispatch records the decision, the resolved target, the approved address set and the risk on the job, so a later scope edit cannot rewrite what was allowed. Start re-evaluates the stored authorization against the current scope and compares the current DNS answer with the recorded set; a changed answer is denied (`address_changed`) instead of followed. A redirect is evaluated as a new target rather than inherited, and a chain is allowed only when every hop is in scope.
- Denials are recorded, not thrown away: the job ends `DENIED`, its event timeline keeps the machine reason, and the audit summary carries a human sentence from `describeDenial`.
- Workers: a registered `ExecutionWorker` declares capabilities and an egress allowlist and must heartbeat. Dispatch only queues to a worker whose allowlist covers the target; a registered but unheard-from worker is ineligible, and a job with no eligible worker is denied (`no_eligible_worker`) rather than waiting indefinitely.
- Job timeline: `ExecutionJobEvent` is append-only (`REQUESTED`, `DISPATCH_DENIED`, `QUEUED`, `STARTED`, `COMPLETED`, `CANCELLED`, review events), which is what an operator reads to answer why a job did or did not run. A `HIGH`-risk job is created `PENDING_REVIEW`, and approval re-runs the dispatch check, including the DNS comparison, before it queues.
- Cancellation is a request, not a status change: the worker holding the lease decides, a completion report that arrives afterwards loses to the cancellation, and repeating the request is idempotent. A cleanup pass cancels reviews left undecided and fails jobs whose lease expired, so nothing stays non-terminal forever.

The routes are `/api/v1/organizations/:orgSlug/engagements` (scope, authorizations, jobs) and `/api/v1/organizations/:orgSlug/execution` (workers). This revision has no console screen for any of them; see the limitations below.

### Audit trail

Appends are transactional with the mutation, have a per-organization advisory lock, and are chained with SHA-256 over a canonical serialization (`sequence`, previous hash, actor, action, outcome, target, summary, metadata, timestamp). A database trigger rejects `UPDATE` and `DELETE`. `GET /api/v1/organizations/:orgSlug/audit/verify` recomputes the chain and reports the first broken sequence; the audit page exposes the same check.

Authentication activity lives in a second trail, `auth_events`, because a sign-in happens before any organization is known and chaining it into a tenant would be a fiction. Better Auth's after-hook writes `auth.signed_in` (password, sign-up, or OIDC), `auth.sign_in_failed`, `auth.second_factor_succeeded`, `auth.second_factor_failed`, and `auth.two_factor_disabled`; a session delete hook writes `auth.session_ended`, which covers sign-out, revocation, and the session rotation that follows a second-factor change. A row carries the account it resolved to, the request address and user-agent, and a small metadata map — never the password, the second factor, or the address an attacker typed at a failed sign-in. Writes are best-effort and never fail the authentication request, the table is append-only by its own trigger, and the only reader is `/account/security`, scoped to the signed-in account.

### Data lifecycle

Operational history is separated from business records. Findings, incidents, assets, compliance evidence, access reviews, and audit events are never removed by a timer: closing them is a human decision, and the audit chain is append-only by trigger. Only derived history is pruned, through one of two paths.

`npm run data:retention` is the operator path: one window over agent runs, delivered or failed alert deliveries, and software inventory rows whose agent stopped reporting, with one `retention.purged` event carrying the cutoff and the counts. A tenant can instead store its own policy through `GET`/`PUT /api/v1/organizations/:orgSlug/settings/retention` — four independent windows for agent runs (90 days by default), alert deliveries (90), software inventory rows (180) and terminal execution jobs (180), each clamped to 7–2555 days so a tenant can keep data longer than the default but cannot claim a one-day window and still hold the record. `POST .../settings/retention/preview` counts what the stored or draft policy would delete without deleting anything; `POST .../settings/retention/purge` requires the literal confirmation string and the owner-only `retention.purge` capability, and records the cutoffs and the authoritative delete counts in the chain. Running execution jobs are exempt whatever the window.

Export has two forms. `npm run data:export` writes one organization's records to a JSON document whose select lists omit every credential (agent token hash and prefix, sealed webhook secret, sessions, password hashes, second-factor secrets) while keeping the audit chain's hashes so the file verifies on its own. `GET /api/v1/organizations/:orgSlug/export/package` adds the portable envelope: the same documents, a manifest listing each one's SHA-256 and byte length together with the organization, signer, key id, package id, creation time and the chain verdict at signing, and an HMAC-SHA256 over the canonical manifest using `EVIDENCE_SIGNING_KEY`. Issuing a package appends `export.package_signed`, written after the documents are assembled so the file never claims an event it does not contain. `npm run evidence:verify-package -- <file>` recomputes every digest and the signature with no database and no account. Neither path runs on a scheduler; deployments wire the CLI into cron or a systemd timer.

### UI surfaces

- Public: landing page, `sign-in` (including a "Continue with …" button when OIDC single sign-on is configured), `sign-up`, `two-factor` challenge.
- Account: `account/security` for TOTP enrollment and backup codes, for the account's own recent authentication activity, and for creating, listing, and revoking personal API keys with a one-time reveal.
- Tenant workspace under `/app/:orgSlug`: dashboard, assets (list and detail), findings (list, detail, status control, JSON import), incidents (list, detail, notes, linked findings), compliance (posture overview, framework detail with attestations, control detail with evidence), agents (list with derived health, registration with one-time token reveal, detail with approval, lifecycle controls, heartbeat interval, compliance mapping, software inventory, run drill-down), identities (inventory with risk signals, registration, detail with lifecycle controls, scope approvals, one-time machine credential issue and rotation, object timeline), access reviews (campaign list with progress and overdue state, detail with per-member retain/revoke decisions and guarded finalization), advisories (import form with a sample entry, feed table, delete), audit (filters and chain verification), members, and settings (organization profile and alert destinations with a recent-delivery table).
- Not in the console: engagements, scope entries, authorizations, execution workers and jobs, the retention policy, and reviewer assignment are API-only in this revision. The evidence package and the plain export are downloads from the API, not a console action.
- Navigation renders only capabilities the current membership holds, but enforcement always happens on the server.

### Known limitations of this phase

- Document-level security headers (CSP, HSTS in production, `X-Frame-Options`, COOP, Permissions-Policy) come from `next.config.ts` for every route. The CSP still allows inline scripts, because Next.js emits its bootstrap script without a nonce; a nonce pipeline is on the roadmap.
- No password reset, email verification, or invitation email flow. People must register before an owner or administrator can add them.
- No file upload. Data leaves through `GET .../export/package` (a signed JSON package whose documents omit every credential) or `npm run data:export` for an operator without a session; neither has a console screen, and the package is not zipped. Compliance evidence links to existing findings, incidents, and assets, or to an external reference string; documents are not stored.
- Retention is an API with no console screen and no scheduler. A purge runs only when an owner calls `POST .../settings/retention/purge` or an operator runs `npm run data:retention`; neither can remove audit events, and deleting a finding in the console still cascades to its `ControlEvidence` rows, so evidence must be exported first if it matters.
- The audit chain is hash-linked but not signed in place. A signed package carries the chain head and an HMAC over its manifest, so a rewrite is detectable only against a package distributed beforehand, and the key is symmetric: whoever can verify can also sign.
- No in-process background worker. Monitoring agents run on their own schedule (cron, `launchd`, Task Scheduler), and the platform never initiates a scan. Execution jobs are a database-backed queue with a registered-worker model, but no worker runtime ships: a worker is an external process that registers, heartbeats, and calls `start` and `complete`. Offline detection and webhook delivery depend on an external scheduler calling `/api/cron/notifications`; with no scheduler configured, alerts queue but are not retried.
- Execution is limited to four declarative capabilities (`DNS_LOOKUP`, `HTTP_PROBE`, `TLS_INSPECTION`, `PORT_SCAN`): no shell, no arbitrary command, no remote response action. Scope understands domains, addresses, CIDRs and URLs, but not wildcard discovery or IPv6 beyond the same CIDR logic. DNS is compared at dispatch, at review approval and at start only, so a target that moves again mid-job is bounded by the duration limit rather than denied.
- A worker is an API client authenticated as a member, not as a distinct worker identity: `start` and `complete` are audited against that user, and the platform trusts the worker to run only the job it started. Per-worker credentials are the next step if workers run on hosts the operator does not fully control.
- Engagements, scope, authorizations, workers and jobs are API-only, so running an engagement needs a session or API key plus the route reference. A campaign's assigned reviewer is enforced by the API but not displayed in the console, and assigning one is a call to `PUT .../access-reviews/:reviewId/reviewer`, so the console cannot explain a refused decision.
- Token rotation is manual and per agent: there is no rotation schedule, no overlap window (the previous token stops working immediately), and no alert when a token is about to expire.
- Signature enforcement is opt-in per deployment. A deployment that leaves `AGENT_REQUIRE_SIGNED_RUNS` unset still accepts an unsigned but valid bearer token, so a leaked token can submit observations without knowing the signing key only until the flag is turned on.
- The monitor's checks are a conservative baseline for Linux, macOS and Windows hosts; they are not a CIS benchmark. Windows coverage is limited to Defender state and signature age, SMBv1, RDP network-level authentication, the Guest account and update recency, and it is read through `powershell.exe` rather than a signed PowerShell script that would resist tampering.
- The advisory feed is imported by hand (a JSON array or `{ "advisories": [...] }`); CyberNorf does not fetch NVD, OSV, or vendor feeds itself, so there is no scheduled sync and no automatic expiry of old entries. Matching happens on the next agent run, not at import.
- Advisory matching compares exact package names within one ecosystem. It does not resolve dependency trees, distributions that rename packages, or kernel and driver versions, and a range that cannot be parsed matches nothing rather than everything.
- The monitor collects `brew list --versions`, `npm ls -g --json`, `pip list`, `dpkg-query`, and `rpm -qa`. macOS applications installed as `.app` bundles (`pkgutil --pkgs`) are not collected, and the report is capped at 800 packages.
- Webhook delivery has no dead-letter review UI beyond the recent-delivery table, and a destination whose signing secret is lost (for example after replacing `BETTER_AUTH_SECRET`) must be deleted and re-created.
- Single sign-on is one OpenID Connect provider configured through `OIDC_*` variables: no SAML, no multiple simultaneous providers, no SCIM. Provisioning is automatic on first verified sign-in, but de-provisioning is manual, so disabling a person at the identity provider does not end their CyberNorf sessions or memberships.
- Personal API keys carry no scopes beyond the owner's live role, no IP allowlist, and no rotation schedule or expiry reminder. A key is a single-organization credential created only from the account settings page; it cannot mint another key, and revoking it is immediate with no overlap window.
- The identity inventory is a governance record, not an authentication store. Suspending a human identity does not end a console session; organization access still comes from the membership. Machine credentials are opaque bearer tokens with one scope (`identity.self.read`), no mTLS or workload binding, and no notification before expiry. Access reviews cover memberships only, are never scheduled automatically, and cannot be reopened once closed. Import connectors (SCIM, OIDC, CSV) do not exist, so every record is entered manually. See [IDENTITY_GOVERNANCE.md](IDENTITY_GOVERNANCE.md).

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

### Reference deployment

`compose.prod.yaml` implements one supported topology: a Caddy reverse proxy that terminates TLS and is the only published service, one `app` container, a one-shot `migrate` container built from the same image, and PostgreSQL on an internal network. The database connection is verified TLS with a certificate generated on first boot, and the app runs unprivileged with a read-only root filesystem. The reasoning and the trade-offs are in [ADR 0004](decisions/0004-production-deployment.md); the operator steps are in [DEPLOYMENT.md](DEPLOYMENT.md). Managed hosting, multiple app instances, and high availability remain open.

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

The Phase 1 entities (`User`, `Organization`, `Membership`, `Asset`, `Finding`, `Incident`, `IncidentNote`, `AuditEvent`), the compliance catalog and attestation entities (`Framework`, `FrameworkControl`, `OrganizationFramework`, `OrganizationControl`, `ControlEvidence`), and the delivered governance and execution entities (`Engagement`, `EngagementScopeEntry`, `EngagementAuthorization`, `ExecutionWorker`, `ExecutionJob`, `ExecutionJobEvent`, `OrganizationRetentionPolicy`, `AccessReview.reviewerId`) exist with migrations. Later phases add:

- `Indicator`, `EvidenceArtifact` for threat intelligence and evidence;
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
- [ADR 0004](decisions/0004-production-deployment.md) — single-host production deployment with a TLS proxy.
- [ADR 0005](decisions/0005-identity-governance.md) — identity governance for human and non-human identities.
- [ADR 0007](decisions/0007-initial-integrations.md) — initial supported integrations.
- [ADR 0008](decisions/0008-scoped-execution-and-evidence-packages.md) — authorized execution and portable evidence packages.

Proposed, not yet validated: [ADR 0006](decisions/0006-initial-customer-segment.md) — initial customer segment and problem.

The following deployment and product decisions remain open:

- cloud-hosted or hybrid deployment (self-hosting is covered by ADR 0004);
- single-tenant versus multi-tenant launch;
- required integrations and data volume;
- whether uploaded samples or security tools will execute in the platform;
- hosting, operating budget, and support expectations.

Record material choices and their trade-offs in architecture decision records as they are approved.
