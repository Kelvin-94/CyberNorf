# ADR 0008: Authorized execution and portable evidence packages

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

Everything before this decision observes and records. Phase 4 adds the first capability that can act on a third-party system, and Phase 5 has to prove to someone outside the platform that the resulting record is intact. Both introduce risk the earlier phases did not have:

- An action taken against a target is only lawful while it is inside a written engagement, inside an approved authorization, inside a time window, and against an address the authorization names. A single check at request time is not enough, because DNS and scope can change between "queued" and "running".
- An export that leaves the platform is trusted only for as long as nobody can edit it. A JSON file with hashes proves nothing if the hashes travel in the same file the attacker controls.

The enterprise brief calls for agentless scanning and remote response. Building an open-ended command channel would create a much larger risk than the one it is meant to demonstrate. This decision records the narrow slice that ships, and the verification model for exported evidence.

## Decision

### Scope is a stored, evaluated rule set

- An `Engagement` belongs to one organization and carries a status (`DRAFT`, `ACTIVE`, `PAUSED`, `CLOSED`) and an `startsAt`/`endsAt` window.
- `EngagementScopeEntry` is either `INCLUDE` or `EXCLUDE` over a `DOMAIN`, `IP_ADDRESS`, `CIDR` or `URL`. Evaluation is deny-by-default: a target must match an inclusion and must not match any exclusion, and an exclusion always wins over a broader inclusion.
- `EngagementAuthorization` requires a separate approver. An authorization whose window has passed, or whose status is not `APPROVED`, denies dispatch regardless of scope. Requesting and approving are distinct actors, checked in the service.
- Capabilities `engagement.read`, `engagement.manage` and `engagement.authorize` are separate so an analyst can prepare scope without being able to authorize it.

### Two enforcement points, not one

- Dispatch evaluates the stored rules and records the decision. `ExecutionJob` stores the resolved target, the approved address set and the risk at that moment, so a later change to scope does not retroactively rewrite what was allowed.
- Start re-evaluates against the recorded authorization and the current scope, and compares the current DNS answer to the recorded address set. A changed answer denies the job instead of following the target somewhere else. Redirects are evaluated as new targets rather than inherited from the original request.
- A job that is denied is recorded as `DENIED` with a human-readable reason; the machine-readable reason stays in the event metadata and the audit log.

### Workers are registered, allowlisted and never selected optimistically

- `ExecutionWorker` declares its capabilities and an egress allowlist. Dispatch only selects a worker whose allowlist covers the target and that has reported a heartbeat; a registered but unheard-from worker is not eligible.
- `ExecutionJobEvent` is an append-only per-job timeline (`REQUESTED`, `DISPATCH_DENIED`, `QUEUED`, `STARTED`, `COMPLETED`, `CANCELLED`, …), which is what an operator reads when asking why a job did or did not run.
- Cancellation is a request recorded on the job, not a status change: the worker that holds the lease decides, and a completion report that arrives afterwards loses to the cancellation. A repeated cancel request is idempotent and does not move the original timestamp.

### Higher-risk work needs a second person

- A job whose risk is `HIGH` is created `PENDING_REVIEW` and can only be approved by someone other than its requester. Rejection is terminal and never queues.
- Cleanup closes reviews and queued jobs that can no longer progress, so a stuck review does not hold a job open indefinitely.

### Evidence packages are signed outside the document

- `GET .../export/package` returns `{ manifest, signature, documents }`. The manifest lists every document with its SHA-256 and byte length, the organization, the signer, the key id and the audit-chain verdict at signing time.
- The signature is `HMAC-SHA256` over the canonical serialization of the manifest, using the same key-sorted, whitespace-free serializer the audit chain uses. A verifier needs the file and the shared key, not this codebase.
- Verification recomputes every document digest, rejects undeclared documents, checks the key id, compares the signature in constant time, and refuses a package whose manifest claims an invalid chain.
- `npm run evidence:verify-package` performs that check offline. Issuing a package appends `export.package_signed` with the package id, key id, signature and digests, written after the document is assembled so the file never claims an event it does not contain.

### Retention is per tenant, with a floor

- `OrganizationRetentionPolicy` stores four independent windows (agent runs, alert deliveries, package snapshots, execution jobs). Every window has a minimum of 7 days and a maximum of 2555.
- `GET .../settings/retention/preview` counts what the stored or draft policy would delete without deleting anything. `POST .../settings/retention/purge` requires the literal confirmation string and the `OWNER` role, and writes `retention.purged` with the cutoffs and the authoritative delete counts.
- Running jobs are never deleted, whatever the window, and audit events are outside the policy entirely: the chain is append-only by trigger.

### Access reviews gain an assigned reviewer

- `reviewerId` on `AccessReview` is enforced, not decorative. Once set, only that account can record decisions; an owner or administrator who is neither the reviewer nor the creator can no longer decide items in their place.
- The reviewer must be an active `ADMIN` or `OWNER` and must not be the person who opened the campaign, which prevents a single administrator from opening a review and recertifying their own access.
- Assignment, reassignment and clearing are each audited with the previous and new reviewer.

## Consequences

- Execution is limited to four declarative capabilities (`DNS_LOOKUP`, `HTTP_PROBE`, `TLS_INSPECTION`, `PORT_SCAN`). There is no arbitrary command execution, no shell, and no remote response action; the worker protocol is a request/result contract, not a remote shell.
- Scope evaluation understands domains, IP addresses, CIDRs and URLs. It does not resolve wildcards against certificate transparency, does not follow HTTP redirects automatically, and does not model IPv6 ranges beyond the same CIDR logic.
- DNS is checked at dispatch and at start. A target that changes its answer mid-job can still be reached by the running process; the mitigation is a short job duration limit, not continuous re-resolution.
- The signing key is symmetric, so anyone who can verify a package can also forge one. Deployments that need third-party verification without sharing signing capability must publish the digest of each issued package out of band; asymmetric signing is a later change.
- Retention deletes derived history only. Findings, incidents, assets, compliance evidence, access reviews and audit events are never removed by a timer; closing or deleting them stays a human decision.
- Reviewer assignment reduces but does not eliminate collusion between two administrators. It makes the collusion explicit in the audit chain, which is the achievable property.
- The capability matrix, audit action list and validation schemas grew again; adding a capability or a retention category requires touching all of them together.
