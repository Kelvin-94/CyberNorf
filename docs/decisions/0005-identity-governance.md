# ADR 0005: Identity governance for human and non-human identities

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

Phase 1 authenticates people through Better Auth and authorizes them through organization memberships and capabilities ([ADR 0002](0002-identity-and-sessions.md), [ADR 0003](0003-authorization-and-audit.md)). That leaves three gaps an enterprise buyer will ask about:

- There is no inventory of the identities that touch the tenant beyond the accounts that happen to hold a membership. Service accounts, monitoring agents, API clients, network devices and containers are invisible, so nobody can answer "which non-human credentials exist, who owns them, and when were they last used?".
- Membership removal is the only revocation path. There is no periodic recertification, no record that a manager reviewed who still needs access, and no way to demonstrate that review to an auditor.
- Long-lived machine credentials have no scoped alternative. A service that only needs to read its own identity currently has to borrow a personal API key with the owner's full live role.

The pasted enterprise specification covers IAM, NAC and NDR. Building that whole stack at once would produce a wide, untested surface. This decision records the Phase 1 slice: governance of identities and their credentials, with access reviews over memberships. Network access control, device posture, directory synchronization and network detection remain later phases.

## Decision

### One inventory for people and machines

- `Identity` carries a `kind` (`HUMAN` or `MACHINE`), a type (user, service account, monitoring agent, API client, server, network device, IoT device, container, other), criticality, lifecycle status, source, an accountable owner, and an optional link to a console user.
- Identifiers are canonicalized to `trim().toLowerCase()` before storage and comparison, and a CHECK constraint enforces the same rule in the database. Case-only duplicate identities therefore cannot exist, and a human record can be matched to a membership by email without a second normalization path.
- A database CHECK keeps `kind = 'MACHINE'` rows free of a `userId`; machines are owned, never logged in as. A trigger rejects `UPDATE` and `DELETE` on `identity_events`, and an integrity trigger rejects rows whose identity belongs to another organization.

### Lifecycle is explicit and forward-only

- Humans are created `ACTIVE`. Machines start `PENDING_APPROVAL` because a credential must not be usable before a person with the `OWNER` role has approved it.
- Permitted transitions are declared in one table (`IDENTITY_STATUS_TRANSITIONS`): `PENDING_APPROVAL → ACTIVE | DEPROVISIONED`, `ACTIVE → SUSPENDED | DEPROVISIONED`, `SUSPENDED → ACTIVE | DEPROVISIONED`. `DEPROVISIONED` is terminal. Anything else is a `conflict`, including reactivating a deprovisioned identity.
- Approval of a machine is owner-only and is checked in the service, not inferred from the `identity.manage` capability. Approving a human identity is rejected as a bad request rather than silently accepted.
- Deleting the owning user nulls `ownerUserId` instead of deleting the identity, and the risk heuristic then reports `UNOWNED_MACHINE`. The record survives the person.

### Machine credentials are scoped, hashed and expiring

- `IdentityCredential` stores a SHA-256 digest and a six-character display prefix; the plaintext (`cnid_…`) is returned exactly once at issue time and never written to the database, logs or audit metadata.
- A credential's scopes must be a subset of the identity's `approvedScopes`, which currently allows one scope, `identity.self.read`. Narrowing `approvedScopes` revokes credentials whose scopes are no longer covered. A machine may hold at most one active credential; issuing another revokes the previous one inside the same transaction, so rotation has no overlap window.
- Credentials have a mandatory expiry (`ttlDays`, default 90, maximum 365). Authenticating checks revocation, expiry, scope, identity status and identity kind, and returns a uniform `401` for every failure so a caller cannot probe which check failed.
- The only consumer is `GET /api/v1/identity/me`, wrapped by `withMachineApi`: bearer token, per-IP and per-credential fixed-window rate limits, and a response that returns identity and credential metadata without the token. A machine credential cannot authenticate a console session or call any tenant route.

### Access reviews snapshot memberships and finalize atomically

- `AccessReview` is a campaign with an `ACTIVE`, `COMPLETED` or `CANCELLED` status and a due date that must be in the future and at most 180 days out. There is no draft state: creating a review snapshots the current memberships immediately.
- `AccessReviewItem` copies the member name, email and role at snapshot time, so the record still reads correctly after a membership changes. Each item is `PENDING`, `RETAIN` or `REVOKE`; a CHECK constraint requires reviewer and timestamp exactly when a decision exists.
- Finalization requires every item to be decided. It disables the membership and deletes its sessions for every `REVOKE`, suspends linked non-deprovisioned identities, and refuses to revoke the last active `OWNER`. The membership changes, session deletions, identity suspensions, audit event and review status commit in one transaction.

### Authorization and audit reuse the existing machinery

- Four capabilities are added: `identity.read` and `access_review.read` for every role, `identity.manage` and `access_review.manage` for `OWNER` and `ADMIN`. The `OWNER` check for machine approval sits on top, matching the existing agent approval rule.
- Every mutation appends a hash-chained audit event (`identity.created`, `identity.credential_issued`, `access_review.completed`, and so on) inside the same transaction, and also writes an `IdentityEvent` for the object timeline. Secret material never enters either record.

## Consequences

- Governance data is only as good as its input. There is no SCIM, OIDC or CSV import, so identities are registered by hand and can drift from the directory. The `UNOWNED_MACHINE`, `PENDING_APPROVAL`, expiry and stale-credential signals make drift visible but do not fix it.
- Suspending a human identity does not end that person's console session; organization access still flows from the membership, and the access-review finalizer is the only code path that disables memberships and deletes sessions in bulk.
- Access reviews cover memberships only. They do not review machine credentials, and cancelling or completing a review does not revoke machine credentials granted during the campaign. Credential revocation remains a per-identity action.
- A machine token is a bearer secret. There is no mTLS, workload attestation, IP allowlist or per-request nonce, so a copied token is usable until it expires or is revoked. The single scope and short TTL bound the damage; they do not prevent replay.
- The risk score is a deterministic heuristic over observable signals, not a model. It is documented, tested at its thresholds, and displayed with the signals that produced it, so an operator can disagree with it.
- Review campaigns are never scheduled automatically and cannot be reopened. A missed review has to be recreated, which produces a second snapshot and a second audit trail rather than mutating the first.
- The capability matrix and audit action set are now larger; adding a new identity type or review decision requires updating validation, the capability module, the audit action list and the role-boundary tests together.
