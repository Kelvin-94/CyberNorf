# Security review: API and tenant isolation

This is the record of the internal review of the HTTP API and the tenant boundary, plus
the brief for the external review that is still required. It is deliberately explicit about
who did the review, because "the author reviewed their own code" is the weakness the
roadmap item exists to remove.

- **Date of this pass:** 2026-11-11
- **Reviewer:** the author of the code (internal, not independent)
- **Status:** internal review complete for the scope below; **external review outstanding**
- **Scope:** every route under `src/app/api/v1/organizations/[orgSlug]`, the user-scoped
  organization list, the authorization helpers in `src/server/authz/`, tenant resolution,
  and the Prisma access patterns in `src/server/services/`.

## Method

The review is mechanical first and analytical second, so it can be repeated and its numbers
checked rather than trusted.

1. **Enumerate handlers and their capability.** Every `route.ts` under the tenant tree was
   parsed for `export const <METHOD> = withTenantApi('<capability>'`, counting route files,
   handlers and any handler whose capability could not be extracted.
2. **Check the read/write rule.** A `GET` must be bound to a capability ending in `.read`;
   every other method must be bound to a mutating capability. Any exception is either fixed
   or listed below with the reason it is deliberate.
3. **Check tenant resolution.** The organization must come from the caller's membership
   (`withTenantApi` resolves the slug against the caller's memberships), never from a body
   or query parameter, and every service must filter on `organizationId`.
4. **Check updates by primary key.** An `update`/`delete` by `id` must be preceded by a
   scoped `findFirst` in the same function, so a guessed id from another tenant cannot be
   written.
5. **Check the framework surface.** No `'use server'` actions, no Prisma access from pages,
   and no route outside the wrapper that touches tenant tables.

Numbers for this pass:

```
route files under src/app/api/v1/organizations/[orgSlug]   62
handlers exported from those files                          89
handlers wrapped by withTenantApi                           89
GET handlers                                                30
GET handlers bound to a .read capability                    29
deliberate GET exceptions                                    1  (export)
handlers found bound to the wrong kind of capability         1  (fixed, see below)
```

## Result

No cross-tenant access path and no capability escalation was found. One misbinding was
found and fixed during the pass, and one latent trap was removed earlier in the same work.

### Fixed: evidence verification was a write behind a read capability

`POST .../compliance/controls/[controlId]/evidence/files/[evidenceId]/verify` was bound to
`compliance.read`. The handler re-hashes the file, writes the integrity outcome to the row
and appends an audit event, so a read-only member could drive database writes and grow the
tenant's audit chain. It is now bound to the mutating `compliance.evidence`
(`ANALYST` and above; `VIEWER` is read-only by design).

### Fixed earlier: `dispatchEventById` had no tenant parameter

`dispatchEventById(eventId)` in `src/server/services/notifications.ts` could load any
organization's event by id. It had no callers, so it was a trap rather than a live path; it
was replaced by `dispatchEventForOrganization(organizationId, eventId)`, which scopes the
lookup and cannot be called without a tenant.

### Deliberate exception: `GET .../export` is bound to `export.download`

The export returns a file, so it is a `GET`, but it is not an ordinary read: it returns the
whole tenant in one response, including the audit chain and every member's email. Binding
it to `export.download` rather than `export.read` is intentional — `OWNER`, `ADMIN` and
`ANALYST` hold it and `VIEWER` does not, the route is rate limited to five requests per
five minutes, and every download appends `export.downloaded` to the audit chain. The
mechanical rule treats this as an exception, not as a violation.

## Properties confirmed by reading the code

- **Tenant from membership.** `withTenantApi` resolves `orgSlug` through the caller's
  active membership; a non-member gets `404`, not `403`, so the existence of a tenant is not
  disclosed.
- **Capability checks are per handler.** There is no route that authenticates and then
  performs an action without a capability check; every handler in the tree is wrapped.
- **Writes by id are scoped first.** Services fetch the row with `{ id, organizationId }`
  before updating it, and cross-tenant ids return `404`. The negative tests in
  `tests/evidence-files.test.ts`, `tests/identities.test.ts` and `tests/indicators.test.ts`
  exercise this for the newer services.
- **No server actions, no page-level database access.** Pages call services that take the
  tenant context, and the only Prisma access outside the services is the readiness probe.
- **Role changes are constrained.** A non-owner cannot grant `ADMIN` or `OWNER`, the last
  active `OWNER` cannot be removed or demoted, and access-review finalization performs its
  revocations in one transaction.
- **Webhooks cannot be pointed inward.** Destinations resolving to private addresses are
  refused unless the operator opts in, and the resolution is repeated at delivery time to
  close the DNS-rebinding window (`tests/webhook-transport.test.ts`).
- **Evidence paths cannot escape the root.** Blob keys are generated hex, matched against a
  strict pattern, and resolved with a prefix check (`src/server/services/evidence-storage.ts`).
- **Audit rows are append-only.** Database triggers reject `UPDATE` and `DELETE`; the chain
  is verified by the application's own verifier in tests and by the restore drill.

## What this review does not cover

- **Independence.** The reviewer wrote the code. This is the reason the item stays open.
- **Business-logic abuse** (for example, a member with a legitimate capability using it
  destructively). Capability design is reviewed; insider misuse is not modelled.
- **Availability and denial of service** beyond the documented rate limits and body-size
  caps.
- **Cryptography.** The use of AES-256-GCM for sealed secrets and SHA-256 for credential
  digests was checked for correct API order (tag set before final) but not audited as a
  cryptographic design.
- **The browser surface** beyond the CSP and cookie tests in `tests/csp.test.ts`.
- **Dependencies and base images** — separate process in
  [DEPENDENCY_RESPONSE.md](DEPENDENCY_RESPONSE.md).
- **The UI's authorization affordances.** Server-side enforcement is reviewed; whether a
  button is shown to the wrong role is a usability defect, not a boundary.

## Brief for the external reviewer

What to provide:

- A disposable deployment with the production compose file, a seeded database, and
  `EVIDENCE_DIR` on a writable volume.
- Two tenants with `OWNER`, `ADMIN`, `ANALYST` and `VIEWER` accounts in each, plus one
  machine identity and one agent token per tenant.
- API documentation or the route table, and this document.
- Written authorization and a scope statement covering the host, the API and the UI.

What to attempt, at minimum:

1. Reach any tenant record with a credential from the other tenant, across every collection
   and by direct id.
2. Escalate from `VIEWER` to any write, and from `ANALYST`/`ADMIN` to owner-only actions.
3. Drive writes through `GET` handlers, and through the export route with a `VIEWER`.
4. Abuse the evidence upload and download paths (traversal, content type, size, symlinks)
   and the webhook destination checks (private IPs, redirects, DNS rebinding).
5. Tamper with the audit chain and with an evidence blob, then check that verification
   reports it.
6. Attempt session and credential attacks: fixation, CSRF, token replay, expired machine
   credential, revoked membership with a live session.

What counts as a result: a reproducible request/response pair per finding, the impact
demonstrated against the seeded tenants, and a severity. A finding that depends on
operator misconfiguration should say so; it is still a finding, but it is a different one.

The review closes when the report is received, every finding is either fixed with a
regression test or accepted with a written rationale, and this document records the date,
the reviewer and the outcome. Until then, the roadmap item stays unchecked.

## Reproducing the mechanical pass

The pass used a throwaway script that parsed each route file; it is not committed, because
the numbers above are the artifact, not the tool. It counted `export const <METHOD> =
withTenantApi('<capability>'` across every `route.ts` in the tree, including bindings split
across lines. `rg` sees only single-line bindings, so use it as a cross-check and add the
multiline handlers by hand:

```
rg -c "export const (GET|POST|PATCH|PUT|DELETE) = withTenantApi" \
  "src/app/api/v1/organizations/[orgSlug]" | awk -F: '{ total += $2 } END { print total }'
```

Then read each `GET` binding for a `.read` capability. A finding is any handler whose
capability does not match its method, other than the export exception recorded above.
