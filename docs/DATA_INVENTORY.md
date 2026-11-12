# Data inventory and data flow

This is the single list of what CyberNorf stores, where each category lives, how long it
lives, and how it leaves the system. It is written against `prisma/schema.prisma`, the
routes under `src/app/api/v1/`, and the services in `src/server/services/`; when the
schema changes, this file is part of the change.

Scope: the self-hosted deployment described in [DEPLOYMENT.md](DEPLOYMENT.md) — one
console container, one PostgreSQL database, one evidence volume, TLS at the proxy. There
are no subprocessors in the data path. A managed or multi-region offering would need this
document rewritten, not extended.

## Where data lives

| Location | Contents | Protection |
| --- | --- | --- |
| PostgreSQL | Every business record, account, audit event and quota override; see the inventory below. | TLS with `sslmode=verify-full` in production; database credentials in the deployment environment; row access always scoped by `organizationId`. |
| Evidence volume (`EVIDENCE_DIR`) | Uploaded control-evidence blobs, sharded as `<root>/<first two hex>/<32 hex>`, files `0640`, directories `0750`. | Absolute path outside the image; blob key validated against `^[a-f0-9]{32}$` and resolved inside the root; the database row stores the SHA-256 recorded while the bytes were written. |
| Mounted secret files (`SECRETS_DIR`) | One file per allow-listed variable: `BETTER_AUTH_SECRET`, `CRON_SECRET`, `OIDC_CLIENT_SECRET`, `EVIDENCE_SIGNING_KEY`. | Read at startup, never written back, group/world-readable files refused; a file wins over the same variable in the environment. |
| Process environment | The same secrets when no files are mounted, plus `DATABASE_URL` and configuration. | `chmod 600` env file in production; `npm run config:check` reports problems without printing values. |
| Container stdout | Structured JSON logs: request lifecycle, startup, delivery outcomes, errors. | Values pass through the audit redactor; access logs stay at the proxy so requests are not logged twice. |
| Browser | Session cookie, CSRF-relevant origin, in-memory page state. | `HttpOnly` cookie, same-origin checks on every mutation. |
| Operator workstation | Export documents, restore-drill reports, rotation output. | Produced only on request; never uploaded anywhere by the product. |

Nothing else is persisted. In particular there is no cache tier, no message broker, no
object-storage bucket and no third-party analytics.

## Inventory

Sensitivity is about the impact of disclosure, not about how likely it is.

| Data | Tables and fields | Why it exists | Sensitivity | Lifecycle |
| --- | --- | --- | --- | --- |
| Accounts | `user` (name, email, verification flag), `account` (provider ids, password hash, OIDC tokens), `verification`, `session` (token, expiry, IP, user agent), `twoFactor` (encrypted TOTP secret, backup codes) | Sign-in, sessions, second factor | High | Until the account is deleted; sessions expire after eight hours of inactivity and are deleted on sign-out, password change and access revocation |
| Authentication history | `auth_events` (event type, outcome, IP, user agent) | Show the account what happened on it | Medium | Append-only; not purged by the retention script |
| Personal API keys | `user_api_keys` (SHA-256 hash, six-character prefix, scopes, expiry, last use) | Automation without a browser session | High | Until revoked or expired; the plaintext is shown once and never stored |
| Tenant | `organizations` (name, slug, tier), `memberships` (role, status) | Tenancy and authorization | Low | No automatic purge; tenant removal is an operator procedure |
| Identity inventory | `identities` (kind, type, identifier, owner, criticality, lifecycle status), `identity_credentials` (SHA-256 hash, prefix, scopes, expiry), `identity_events` (append-only timeline) | Know which humans and machines exist, who owns them, and what they may do | High | Identities until deprovisioned or deleted; events append-only |
| Access reviews | `access_reviews` (including `reviewerId`, the assigned reviewer), `access_review_items` (member snapshot, role at review, decision, reviewer, note) | Demonstrate periodic recertification | Medium | Kept as the record of the review; no automatic purge |
| Engagements | `engagements` (status, window), `engagement_scope_entries` (kind, target type, value), `engagement_authorizations` (requester, approver, window, status) | Record who authorized which testing against which targets, and until when | Medium–High (targets reveal infrastructure) | Permanent; scope and authorization history is the record |
| Execution | `execution_workers` (name, capabilities, egress allowlist, heartbeat), `execution_jobs` (capability, target, resolved addresses, denial reason, timings, requester), `execution_job_events` (append-only timeline) | Control what ran or was denied, and prove it afterwards | Medium–High (targets and results) | Jobs and events until the tenant retention window (default 180 days); workers until revoked |
| Retention policy | `organization_retention_policies` (four windows, change time) | Let a tenant set its own derived-history windows | Low | One row per organization, overwritten on change |
| Security work | `assets`, `findings`, `incidents`, `incident_notes` | The case record: what is exposed, what is wrong, what was done | Medium–High (free text can contain customer details) | Permanent; never auto-purged |
| Monitoring | `agents` (token hash, prefix, scopes, heartbeat), `agent_runs` (check results), `software_items` (installed packages) | Endpoint health and package inventory | Medium | Runs and software inventory rows older than the retention window are purged; agents until revoked |
| Intelligence | `advisories` (imported feed), `indicators` (normalised value, provenance, confidence, first/last seen), `indicator_links` (finding or incident, relation) | Vulnerability matching and IOC tracking with provenance | Medium | Permanent; never auto-purged |
| Alerting | `notification_channels` (URL, sealed signing secret), `notification_events` (payload, status, attempts, last error) | Deliver alerts and prove what was delivered | Medium (payloads can name assets) | Channel until deleted; terminal deliveries older than the retention window are purged, pending ones are never purged |
| Compliance | `frameworks`, `framework_controls` (global catalog), `organization_frameworks`, `organization_controls`, `control_evidence`, `check_control_maps` | Attestation and control evidence | Medium | Permanent; evidence files can be deleted through the API when they are not the last support for an implemented control |
| Evidence files | `control_evidence` file columns (name, content type, size, SHA-256, capture time, integrity status, blob key) plus the blob on disk | Prove a control was supported and that the file has not changed | Medium–High | Row and blob until deleted; `npm run evidence:verify` re-hashes and records the result |
| Audit trail | `audit_events` (actor, action, target, outcome, metadata, IP, user agent, previous hash, hash) | Tamper-evident history of privileged operations | High (integrity) | Append-only, hash-chained per organization; database triggers reject `UPDATE` and `DELETE`; never purged |
| Quotas | `organization_quotas` (per-resource overrides) | Operator-managed limits above the tier defaults | Low | Until an operator changes or removes the override |
| Configuration record | `system_settings` (`config.fingerprint`: keyed digest of the effective configuration, updated timestamp) | Detect that configuration changed between restarts, and record when | Low (a digest, not the values) | One row, overwritten on change |
| Rate limits | `rateLimit`, `api_rate_limits` | Bound request frequency | Low | Expired windows are swept by the retention job |

Field-level notes that matter for a review:

- No plaintext credential is stored anywhere: personal API keys, agent tokens and machine
  credentials are kept as SHA-256 digests plus a display prefix. The plaintext is returned
  once, at issue time.
- Webhook signing secrets are sealed with a key derived from `BETTER_AUTH_SECRET`, so a
  database dump alone does not yield a usable signing key.
- TOTP secrets are encrypted with the same secret; rotating `BETTER_AUTH_SECRET` makes them
  unreadable, which is why [SECRETS.md](SECRETS.md) treats that rotation as a lockout event.
- Session tokens are stored in the `session` table because Better Auth validates them
  there. The database is therefore trusted with live session material; this is one reason
  database access is restricted to the application role and backups are treated as
  sensitive.
- Audit metadata is written by the application and redacted by the same function used for
  logs. It must never contain a token, a password or a secret value.

## Data flow

```
                         ┌──────────────────────────────┐
   browser ──1──────────▶│  TLS proxy → Next.js app      │
                         │  (session cookie, CSRF check) │
   agent ────2──────────▶│                               │
   machine ──3──────────▶│  route handler → service      │
   IdP ──────4──────────▶│  → Prisma / fs / fetch        │
   cron ─────5──────────▶│                               │
                         └───┬────────┬─────────┬────────┘
                             │6       │7        │8
                             ▼        ▼         ▼
                       PostgreSQL  EVIDENCE_DIR  webhook receiver
                             ▲
   operator CLI ─────9───────┘        operator ──10──▶ export file on disk
```

1. **Browser → app.** Sign-in, MFA, and every tenant action. The session cookie is
   `HttpOnly`; state-changing requests are checked against the request origin; the tenant
   is resolved from the caller's membership, never from the URL alone.
2. **Agent → app.** The bundled monitor presents an agent token (`cna_…`), which is
   compared against a stored hash. Run payloads may carry an HMAC signature derived from
   the token; `AGENT_REQUIRE_SIGNED_RUNS=true` refuses unsigned submissions.
3. **Machine identity → app.** A scoped machine credential (`cnid_…`) is accepted only on
   `/api/v1/identity/me`, with its own rate limits and a uniform `401` for every failure.
4. **Identity provider ↔ app.** OIDC authorization-code flow with PKCE; the discovery
   document and JWKS are fetched from the issuer, and a verified email is required before
   an existing local account is linked.
5. **Scheduler → app.** `GET /api/cron/notifications` with `Authorization: Bearer
   $CRON_SECRET` drains the alert outbox. There is no background worker in the app.
6. **App → PostgreSQL.** All reads and writes, over TLS in production. Tenant tables are
   only queried with an `organizationId` predicate; the audit chain is appended in the
   same transaction as the change it describes.
7. **App → evidence volume.** Uploads are streamed once to disk while being hashed, with
   the size limit enforced mid-stream; a failed upload removes its partial file. Reads
   stream the blob back after an authorization check, and verification re-hashes it.
8. **App → webhook receiver.** Alert payloads signed with the channel's sealed secret.
   Destinations must resolve to public addresses unless
   `NOTIFY_ALLOW_PRIVATE_WEBHOOKS=true`, which closes the SSRF and DNS-rebinding paths.
9. **Operator CLI → database and secrets.** `data:export`, `data:retention`,
   `db:restore-drill`, `quota`, `evidence:verify` and `secrets:rotate` run on the host with
   operator credentials. They are not tenant-authenticated and are documented as
   operator-only.
10. **App → export file.** `GET /api/v1/organizations/[orgSlug]/export` requires the
    `export.download` capability, is rate limited to five requests per five minutes, is
    marked `Cache-Control: private, no-store`, and appends `export.downloaded` to the audit
    chain. The document contains business records and the audit trail with its hashes; it
    excludes credential material (see the export `EXCLUDED` list and `EXPORT_VERSION` in
    `src/server/services/export.ts`). The signed variant, `GET .../export/package`, wraps
    the same document in a manifest with a per-document SHA-256 and an HMAC-SHA256
    signature (`EVIDENCE_SIGNING_KEY`) and appends `export.package_signed`; the offline
    verifier needs neither a session nor the database.

## Trust boundaries

| Boundary | What crosses it | Control |
| --- | --- | --- |
| Browser ↔ app | Credentials, session cookie, tenant input | TLS, origin check, capability checks, input validation, rate limits |
| Monitored host ↔ app | Agent token, run payload | Token hash comparison, optional signature, per-agent scopes, replay-safe run records |
| Identity provider ↔ app | OIDC codes and tokens | PKCE, state/nonce, verified email, allow-listed issuer |
| App ↔ database | Every tenant record | TLS in production, least-privilege database role, tenant predicate on every query |
| App ↔ evidence volume | File bytes and hashes | Path validation inside the root, streaming hash, size and content-type limits, integrity sweep |
| App ↔ webhook receiver | Alert payload and signature | Public-address resolution, sealed signing secret, bounded retries |
| App ↔ execution worker | Job instruction (capability, target, approved addresses) and result | Worker registered by a member with `execution.manage`, egress allowlist and heartbeat decide eligibility, start re-checks DNS, lease expiry fails a stale job |
| Operator ↔ host | Database credentials, secrets, exports | OS access control, `chmod 600` env files, no secret values in output |
| Tenant ↔ tenant | Nothing | Membership-derived tenant context on every route and page; negative tests in `tests/tenant-isolation.test.ts` |

## Retention and deletion

- **Purged automatically** by `npm run data:retention` (dry-run first, audited with
  `retention.purged`): agent runs older than the cutoff, terminal notification deliveries
  older than the cutoff, software inventory rows not seen since the cutoff, and expired rate-limit
  windows. A tenant can override the windows for agent runs, alert deliveries, package
  snapshots and terminal execution jobs through `organization_retention_policies`
  (`POST .../settings/retention/purge`), which is owner-only, requires a literal confirmation
  and records the cutoffs and counts in the same audit event. Running jobs are exempt.
- **Never purged automatically:** findings, incidents, assets, identities, access reviews,
  indicators, compliance evidence, audit and authentication events. These are the record the
  product exists to keep; removing them is a tenant or operator decision, not a background
  job.
- **Tenant deletion:** there is no in-product organization delete. The schema declares
  `onDelete: Cascade` from `organizations`, but the audit triggers reject deleting an
  audit row, so a cascading organization delete would fail once the chain exists. Removing
  a tenant is therefore an operator procedure — database plus `EVIDENCE_DIR` directory —
  and evidence blobs are never removed by a database cascade.
- **Deleted individually:** evidence files through `DELETE
  /api/v1/organizations/[orgSlug]/compliance/controls/[controlId]/evidence/files/[evidenceId]`,
  which removes the blob as well as the row and refuses to leave an implemented control
  without evidence.
- **Leaves the system** only as an authorized export (§10 above) in either form — plain
  JSON or signed package — as an operator-run `data:export`, or as a database backup
  produced by the deployment procedure. Nothing is sent to a third party except alert
  deliveries to channels the tenant configured.

## Backups and residency

Backups are the operator's responsibility and are described in
[DEPLOYMENT.md](DEPLOYMENT.md#operating-it): the database dump, the evidence directory and
the environment file must be captured together, because a database restored without its
evidence volume will report every file as `MISSING` until the volume is restored too.
`npm run db:restore-drill` produces the JSON report that proves a restore is complete and
that the audit chains still verify. Data residency follows the host the operator chooses;
there are no subprocessors in the data path.

## Keeping this document true

Add a row when a new table or file location starts holding data, remove one when it stops,
and update the retention section when the purge scope changes. A schema change that adds a
column capable of holding personal or credential data is incomplete until this file and
[THREAT_MODEL.md](THREAT_MODEL.md) say what it is and who may read it.
