# Local development

This guide runs the CyberNorf Phase 1 application locally: authenticated, multi-tenant SOC workflows for assets, findings, incidents, members, and audit. It is a development setup only; see [ARCHITECTURE.md](ARCHITECTURE.md) for the implemented design and the known limitations that block production use.

## Prerequisites

- Node.js 24 LTS and npm
- Docker with Docker Compose, or a PostgreSQL 17 server
- Git

## Setup

From the repository root:

```sh
cp .env.example .env
npm ci
docker compose up -d database
```

Then edit `.env`:

1. Replace `BETTER_AUTH_SECRET` with a real random value, for example `openssl rand -base64 48`. Production requires at least 32 characters and refuses to start otherwise; development falls back to a well-known placeholder so the app still boots without it, which is unsafe outside local work.
2. Confirm `BETTER_AUTH_URL` matches the origin you browse (`http://localhost:3000` by default). It is the trusted origin for cookies and for the same-origin check on state-changing requests.

The example database credentials are for the local Compose service only. Do not reuse them in shared, hosted, or production environments. Keep `.env` and `.env.test` local; only `.env.example` belongs in version control.

Compose publishes PostgreSQL on `POSTGRES_HOST_PORT` (default `5432`). If that port is already in use — common on macOS where PostgreSQL is installed locally — set `POSTGRES_HOST_PORT` in `.env` to a free port (for example `55432`) and change the port in `DATABASE_URL` to match.

`npm ci` installs the checked-in `package-lock.json` reproducibly. Run `npm install` when intentionally changing dependencies, then commit the updated manifest and lockfile together.

### Environment variables

| Variable                        | Required                | Purpose                                                                                   |
| ------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------- |
| `DATABASE_URL`                  | yes                     | PostgreSQL connection string used by Prisma and the app.                                  |
| `BETTER_AUTH_SECRET`            | yes outside development | Signs sessions and encrypts second-factor secrets. 32+ characters in production.          |
| `BETTER_AUTH_URL`               | yes                     | Public origin. Used for cookies, trusted origins, and the same-origin check.              |
| `POSTGRES_HOST_PORT`            | Compose only            | Host port mapped to the PostgreSQL container.                                             |
| `CRON_SECRET`                   | for alert sweep         | Bearer token the scheduler presents to `/api/cron/notifications`; 24+ chars.              |
| `NOTIFY_ALLOW_PRIVATE_WEBHOOKS` | no                      | `true` allows alert destinations on loopback/private addresses (internal collector only). |
| `AGENT_REQUIRE_SIGNED_RUNS`     | no                      | `true` refuses unsigned agent submissions; set it once every host runs a signing monitor. |

If Prisma reports `P1001: Can't reach database server` while `nc -z 127.0.0.1 <port>` succeeds, replace `localhost` with `127.0.0.1` in the connection string. Some macOS setups resolve `localhost` to IPv6 first, where the container is not listening.

### Transport security in production

A production build refuses to serve traffic over an insecure link. `src/instrumentation.ts` calls `assertSecureTransport()` before the first request and the process answers `500` to everything if either check fails:

- `BETTER_AUTH_URL` must be an `https://` origin. Session cookies are only marked `Secure` when `NODE_ENV=production`, so a plain-http deployment would hand out cookies the browser never sends back. `localhost`, `127.0.0.1` and `[::1]` are exempt because nothing leaves the machine and browsers treat loopback as a secure context.
- `DATABASE_URL` must include `sslmode=require` (or `verify-ca` / `verify-full` with a CA) when the database is remote. Loopback hosts and unix sockets are exempt because that traffic never leaves the host.

TLS itself is terminated in front of the app. `src/proxy.ts` redirects anything that is not `x-forwarded-proto: https` with a `308`, so the proxy has to forward that header. `next.config.ts` adds HSTS, CSP, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy` to every response; HSTS is production-only so local development is never pinned to https.

The bundled Compose database stores no TLS certificate and is bound to `127.0.0.1`, so it is for local development only. Use a managed PostgreSQL with TLS for anything shared.

## Database and migrations

The Phase 1 schema and its migrations are checked in:

- `20261102114540_phase1_soc_foundation` — identity, organizations, assets, findings, incidents, and audit tables.
- `20261102114550_audit_append_only_guard` — the trigger that rejects `UPDATE` and `DELETE` on `audit_events`.
- `20261102115532_organization_description` — organization descriptions.
- `20261104095010_compliance_frameworks` — compliance catalog (`frameworks`, `framework_controls`), tenant adoption and attestation tables, control evidence, the curated framework seed (61 controls across SOC 2, ISO/IEC 27001, NIST CSF 2.0, PCI DSS, and GDPR), and the single-target and review-date CHECK constraints.
- `20261104095310_compliance_control_position` — explicit `position` on catalog controls so the UI lists them in standard order. Both migrations are safe to replay on an empty database.
- `20261108130823_agent_monitoring` — `agents` and `agent_runs`, the `AGENT` finding source and audit actor.
- `20261109090337_check_control_maps` — `check_control_maps`, joining an observed check id to a tenant control.
- `20261109092103_agent_heartbeats_notifications` — agent cadence and outage marker columns, plus `notification_channels` and `notification_events`.

Apply them to the development database:

```sh
npm run db:migrate:dev
```

After editing `prisma/schema.prisma`, create and apply a migration in one step:

```sh
npm run db:migrate:dev -- --name describe_your_change
```

Apply checked-in migrations to staging or production with `npm run db:migrate:deploy`, and inspect state with `npm run db:migrate:status`. Prisma 7 does not regenerate Prisma Client automatically, so run `npm run db:generate` after schema changes. Do not run `migrate dev` against production databases.

The `audit_events` trigger is part of the schema, not application code. Manual `UPDATE` or `DELETE` statements against that table fail with SQLSTATE `42501`, which is intended. To start over locally, drop and recreate the database rather than editing audit rows.

## Tests

Unit tests run anywhere. Integration tests need a separate PostgreSQL database whose name contains `test`; the harness refuses to run against any other database, and it truncates tables between tests.

```sh
createdb -h 127.0.0.1 -p 55432 -U cybernorf cybernorf_test   # once, or use psql
```

Create `.env.test` (gitignored) with:

```sh
DATABASE_URL="postgresql://cybernorf:cybernorf@127.0.0.1:55432/cybernorf_test?schema=public"
BETTER_AUTH_SECRET="test-only-secret-value"
BETTER_AUTH_URL="http://localhost:3000"
NODE_ENV="test"
```

Then:

```sh
npm run test:db:prepare   # applies migrations to the test database
npm test                  # unit + integration tests
npm run test:unit         # unit tests only
```

Tests run with `--test-concurrency=1` because each file resets the shared test database.

Test coverage in this phase:

- `src/server/authz/roles.test.ts` — capability matrix, fail-closed unknown roles, second-factor rules.
- `src/server/domain/transitions.test.ts` — allowed and rejected finding and incident transitions.
- `src/server/audit/canonical.test.ts` — canonical serialization and hash stability.
- `src/server/validation/findings.test.ts` — input normalization and bounds.
- `src/server/config.test.ts` — production transport rules: https origin, loopback exemption, and TLS for remote databases.
- `tests/tenant-isolation.test.ts` — cross-tenant reads, writes, relationship abuse, disabled memberships, and MFA enforcement.
- `tests/audit-integrity.test.ts` — every mutation appends a linked event, rows cannot be updated or deleted, chains stay valid per organization.
- `tests/findings-workflow.test.ts` — the acceptance workflow and import deduplication.
- `tests/rate-limit.test.ts` — window accounting and `429` behavior.
- `tests/regression-defects.test.ts` — defects found by the runtime audit, kept as regressions: in-payload duplicate imports, concurrent import races, fingerprint stability across renames and asset deletion, session revocation scope on membership removal, active-only member counts, slug collisions, and case-insensitive member lookup.
- `src/server/domain/compliance.test.ts` — weighted posture scoring, band thresholds, and the evidence/attestation rules.
- `tests/compliance.test.ts` — adopt, re-adopt conflict, implement-without-evidence refusal, cross-tenant evidence rejection, review-date stamping, last-evidence protection, withdrawal guards, catalog ordering, and per-tenant control isolation.
- `src/server/domain/agents.test.ts` — token shape and hashing, token TTLs, one-time prefix, lifecycle table, scope defaults, and derived run status.
- `tests/agents.test.ts` — builtin activation, external approval (owner-only, narrowing-only), token authentication, run ingestion and finding deduplication, closed-finding suppression, suspension/resumption/revocation, cross-tenant isolation, and audit-chain growth.

The database-backed suites rely on `TRUNCATE ... RESTART IDENTITY CASCADE` rather than row deletes, because `audit_events` rejects `DELETE` at the trigger level. `frameworks` and `framework_controls` are excluded from the truncate: they are seeded by migration and shared by every tenant.

## Compliance module

The compliance surface lives in `src/server/services/compliance.ts`, `src/server/domain/compliance.ts`, and `src/app/app/[orgSlug]/compliance/**`. Tenant-scoped endpoints are mounted under `/api/v1/organizations/:orgSlug/compliance`:

| Method and path                                 | Capability            | Purpose                                                                      |
| ----------------------------------------------- | --------------------- | ---------------------------------------------------------------------------- |
| `GET /compliance`                               | `compliance.read`     | Weighted posture, per-framework cards, integrity warnings, and risk signals. |
| `GET /compliance/frameworks`                    | `compliance.read`     | Catalog with this tenant's adoption state.                                   |
| `POST /compliance/frameworks`                   | `compliance.manage`   | Adopt a framework (accepts a framework id or code).                          |
| `GET /compliance/frameworks/:frameworkKey`      | `compliance.read`     | Controls, attestations, evidence, and framework activity.                    |
| `DELETE /compliance/frameworks/:frameworkKey`   | `compliance.manage`   | Withdraw an adoption; refused while evidence is attached.                    |
| `PATCH /compliance/controls/:controlId`         | `compliance.manage`   | Move the attestation status, owner, review date, or notes.                   |
| `POST /compliance/controls/:controlId/evidence` | `compliance.evidence` | Attach finding, incident, asset, or reference evidence.                      |
| `DELETE /compliance/evidence/:evidenceId`       | `compliance.evidence` | Remove evidence; refused for the last support of an `IMPLEMENTED` control.   |
| `GET /compliance/options`                       | `compliance.read`     | Members and evidence targets for the forms.                                  |

`compliance.manage` and `compliance.evidence` are mutating capabilities, so owners and admins need a TOTP second factor before either succeeds.

## Agent monitoring

The agent surface lives in `src/server/services/agents.ts`, `src/server/domain/agents.ts`, `src/server/api/agent.ts`, `src/app/app/[orgSlug]/agents/**`, and `scripts/agent/monitor.mjs`. Console endpoints are mounted under `/api/v1/organizations/:orgSlug/agents` and use the normal cookie session:

| Method and path                 | Capability     | Purpose                                                                    |
| ------------------------------- | -------------- | -------------------------------------------------------------------------- |
| `GET /agents`                   | `agent.read`   | Agent list with status and run counts.                                     |
| `POST /agents`                  | `agent.manage` | Register an agent; a builtin one is activated and its token shown once.    |
| `GET /agents/:agentId`          | `agent.read`   | Record, scopes, credential metadata, runs, and raised findings.            |
| `PATCH /agents/:agentId`        | `agent.manage` | Set or clear the expected reporting interval (`expectedIntervalMinutes`).  |
| `DELETE /agents/:agentId`       | `agent.manage` | Revoke permanently (owner only).                                           |
| `POST /agents/:agentId/approve` | `agent.manage` | Approve a pending agent and issue its token (owner only).                  |
| `POST /agents/:agentId/suspend` | `agent.manage` | Suspend; the token keeps its scopes but is rejected until resume.          |
| `POST /agents/:agentId/resume`  | `agent.manage` | Resume a suspended agent (owner only).                                     |
| `GET /check-maps?agentId=`      | `agent.read`   | Observed checks, their last status, their mapped controls, and the picker. |
| `POST /check-maps`              | `agent.manage` | Map one check id to one control of an adopted framework.                   |
| `DELETE /check-maps/:mapId`     | `agent.manage` | Stop automatic evidence for that check and control.                        |

Agents call two routes that accept only a bearer token, never a session cookie:

| Method and path               | Scope            | Purpose                                                             |
| ----------------------------- | ---------------- | ------------------------------------------------------------------- |
| `GET /api/v1/agents/me`       | `monitor.read`   | The agent's own record, scopes, and expiry.                         |
| `GET /api/v1/agents/me/runs`  | `monitor.read`   | The agent's recent runs.                                            |
| `POST /api/v1/agents/me/runs` | `monitor.report` | Submit a run; counts, status, and findings are derived server-side. |

### Running the builtin monitor

Register a `BUILTIN` agent in the console, copy the token from the one-time reveal, then run the monitor on the host you want to check:

```sh
CYBERNORF_AGENT_TOKEN=<token> node scripts/agent/monitor.mjs --org-url http://localhost:3000
node scripts/agent/monitor.mjs --dry-run                 # collect and print, submit nothing
node scripts/agent/monitor.mjs --out report.json         # air-gapped host: write only
node scripts/agent/monitor.mjs --in report.json --token <token>   # submit later
```

Each check carries two labels: `title` names the control that was evaluated (`Host firewall state`) and is what the run table shows, while `findingTitle` states the faulty condition (`Host firewall is disabled`) and is used as the finding title when the check fails. Custom agents should send both; when `findingTitle` is omitted the server falls back to `title`, which is why the field is optional rather than required.

The script needs nothing but Node: no npm install and no cloud API. It reads local evidence only (`sshd_config`, `sudoers`, `socketfilterfw`, FileVault, `lsof`, file permissions, guest account and autologin). A check whose evidence is unreadable returns `SKIP`, and a check that throws is reported `SKIP` rather than passed. Exit codes: `0` submitted or dry-run, `1` submission failed, `2` bad usage. A report written with `--out` is mode `0600`.

### Compliance mapping

An agent reports technical evidence; a framework asks for control evidence. `CheckControlMap` joins the two: an operator maps a check id (for example `access.host-firewall`) to a control of a framework the tenant has already adopted, on the agent detail page under **Compliance mapping**. Only observed checks are offered, because the list is built from the last 20 runs rather than from documentation.

When a mapped check fails and its finding is created or refreshed, the run stores a `ControlEvidence` row of kind `FINDING` against that control, and appends `compliance.evidence_added` with `actorType = AGENT`. The attachment is idempotent per finding: a check that keeps failing does not pile up duplicates, and a mapping added later still receives evidence on the next failing run. Removing a mapping stops future attachments and leaves the evidence already filed in place, because that is audit history.

Mapping requires the `agent.manage` capability (owner or administrator); reading the mapping only needs `agent.read`. `agent.check_mapped` and `agent.check_unmapped` are audited against the framework record.

### Offline detection and alerts

An agent that runs on a host nobody watches can fail silently. Setting an expected interval on the agent (`PATCH /agents/:agentId` with `expectedIntervalMinutes`, 5 to 10080, or `null` to disable) makes silence observable. Health is derived from that interval and the last run: within one interval is `ONLINE`, one missed interval is `STALE`, two are `OFFLINE`, and an agent that is not `ACTIVE` or has no interval is `UNKNOWN`. Only `OFFLINE` raises an alert, so a single late run never pages anyone. Both the agent list and the agent detail page show the state.

Alert destinations are ordinary HTTPS endpoints:

| Method and path                        | Capability            | Purpose                                                 |
| -------------------------------------- | --------------------- | ------------------------------------------------------- |
| `GET /notification-channels`           | `notification.read`   | Destinations, recent deliveries, and scheduling state.  |
| `POST /notification-channels`          | `notification.manage` | Add a signing secret and endpoint URL.                  |
| `DELETE /notification-channels/:id`    | `notification.manage` | Remove the destination and its delivery history.        |
| `POST /notification-channels/:id/test` | `notification.manage` | Queue and immediately attempt one signed test delivery. |

A destination must be an absolute HTTPS URL with no embedded credentials, and it must not resolve to loopback, private, link-local, or reserved addresses. `NOTIFY_ALLOW_PRIVATE_WEBHOOKS=true` lifts the address restriction for a deployment whose collector is internal; the URL policy is re-checked on every delivery, not only when the destination is created. Redirects are refused.

The signing secret is sealed with AES-256-GCM using a key derived from `BETTER_AUTH_SECRET`, never returned by the API, and not written to the audit trail (only the host is recorded). Replacing `BETTER_AUTH_SECRET` therefore makes existing destinations undeliverable: delete and re-add them with the same secret value.

Each delivery is a `POST` with `content-type: application/json` and these headers:

- `x-cybernorf-event` — `AGENT_OFFLINE`, `AGENT_RECOVERED`, or `TEST`.
- `x-cybernorf-delivery` — the event id, usable as an idempotency key.
- `x-cybernorf-timestamp` — Unix seconds.
- `x-cybernorf-signature` — `sha256=` followed by the hex HMAC-SHA256 of the timestamp, a literal dot, and the raw body. Compare it in constant time and reject timestamps older than a few minutes to bound replay.

Delivery is retried with backoff (1, 5, 15, 60, and 240 minutes) up to five attempts, after which the event is `FAILED` and the destination records the last error. A failed attempt never loses the event. An outage alert still queued when the host reports again is dropped and replaced by the recovery alert. Attempts are claimed atomically, so two overlapping sweeps cannot deliver the same event twice.

The sweep itself is a single authenticated route, `/api/cron/notifications`:

```sh
CRON_SECRET=$(openssl rand -base64 32)   # store it in the environment
curl -fsS -H "Authorization: Bearer $CRON_SECRET" http://localhost:3000/api/cron/notifications
```

It answers `503` when `CRON_SECRET` is unset or shorter than 24 characters, and `401` for a wrong token, so a deployment that forgets the variable cannot be triggered by anyone who finds the route. Run it every minute from cron, a systemd timer, or a platform scheduler. The response reports how many agents were checked, how many went offline or recovered, how many alerts were queued, and the delivery counts.

### Software inventory and advisories

A run may also carry the packages the host has installed (`inventory`, at most 800 entries). The server resolves the report hostname to a tenant asset, creating a `HOSTNAME` asset the first time a host reports, and replaces that agent's snapshot with the list, so a package that was uninstalled stops counting. The agent detail page shows the snapshot under **Software inventory**, annotated with the advisories that match.

Advisories are imported per tenant; there is no cloud feed and nothing is fetched from the Internet:

```sh
curl -fsS -X POST https://cybernorf.example/api/v1/organizations/acme/advisories \
  -H 'content-type: application/json' --cookie "$SESSION" \
  -d '{"advisories": [{
        "identifier": "CVE-2024-21538",
        "packageName": "cross-spawn",
        "ecosystem": "NPM",
        "summary": "ReDoS when parsing a crafted argument",
        "severity": "HIGH",
        "affectedRange": ">= 7.0.0, < 7.0.5",
        "fixedVersion": "7.0.5",
        "cvssScore": 7.5,
        "referenceUrl": "https://nvd.nist.gov/vuln/detail/CVE-2024-21538"
      }]}'
```

The console page `/app/:orgSlug/advisories` accepts either that object or a bare JSON array, shows the current feed, and can delete an entry. Importing is idempotent per identifier and package name: a re-import updates the existing row and reports it as updated instead of creating a duplicate, and the whole batch is rejected when the same pair appears twice. At most 500 advisories are accepted per request.

| Method and path          | Capability        | Purpose                                               |
| ------------------------ | ----------------- | ----------------------------------------------------- |
| `GET /advisories`        | `advisory.read`   | Feed list, filtered by search text and ecosystem.     |
| `POST /advisories`       | `advisory.manage` | Import or update a batch; audits `advisory.imported`. |
| `DELETE /advisories/:id` | `advisory.manage` | Remove one entry; audits `advisory.deleted`.          |

`affectedRange` uses npm range syntax (`>= 1.2.0, < 1.2.9`, `^2.0.0`, `1.x`, `1.2.3 - 1.4.0`, `1.2.3 || 2.0.0`) and is validated with the same parser the matcher uses, so a range that cannot be read is rejected instead of being stored as "affects nothing". Debian and RPM version quirks beyond a leading epoch and a package revision, such as `~` ordering, are compared with the general rules; a range that omits the suffix still matches on the numeric release.

Matching happens when a run arrives, not when an advisory is imported:

- A package matches when the ecosystem is identical and the name matches case-insensitively, and `affectedRange` contains the reported version.
- Each match creates one finding per advisory and host, titled `<package> <version> is affected by <identifier>`, with `source = AGENT`, the advisory severity, the CVSS score, the host asset, and remediation naming the fixed version. `cveId` is filled only when the identifier looks like a CVE.
- A later run that still matches refreshes the same finding instead of creating a second one; a finding a person resolved, accepted, or marked a false positive is left closed.
- `finding.created` records the advisory identifier, package, ecosystem, installed version, agent, and run. A host discovered by an inventory report also audits `asset.created`.

To pick up an advisory published after the last run, run the monitor again on that host.

### Scheduling

CyberNorf never initiates a scan, so schedule the monitor on the host itself, for example a `launchd` agent on macOS, a systemd timer on Linux, or a weekly cron entry on a hardened jump host. Suspension is the reversible option when a host is being rebuilt.

### Token rotation and signed runs

An owner can rotate an active agent's credential without losing its run history or check-to-control mappings:

```sh
curl -fsS -X POST https://cybernorf.example/api/v1/organizations/acme/agents/<agentId>/rotate \
  -H 'content-type: application/json' --cookie "$SESSION" -d '{"note": "quarterly rotation"}'
```

The response carries the new token once; the previous token stops authenticating immediately, and the rotation is audited as `agent.token_rotated` with the previous and new prefixes. Update `CYBERNORF_AGENT_TOKEN` on the host before its next run.

Every submission from `scripts/agent/monitor.mjs` is signed. The signature is the HMAC-SHA256 of `<unix seconds>.<raw body>` under a key derived from the agent token (`sha256("cybernorf-agent-signing:v1:" + token)`), sent as:

```
x-cybernorf-timestamp: 1762684800
x-cybernorf-signature: sha256=<hex mac>
```

The server verifies a signature whenever one is present, against the exact bytes received, so a tampered or replayed body is refused even when signing is optional. A timestamp outside a five-minute window is rejected. Set `AGENT_REQUIRE_SIGNED_RUNS=true` to refuse unsigned submissions as well; do that after every host has been updated, because an unsigned report from an older copy of the monitor is rejected outright. Rotating the token also rotates the signing key.

To sign from another runtime, for example an external agent written in Python:

```python
import hashlib, hmac, json, time, urllib.request

body = json.dumps(report).encode("utf-8")
ts = str(int(time.time()))
key = hashlib.sha256(f"cybernorf-agent-signing:v1:{token}".encode()).digest()
sig = "sha256=" + hmac.new(key, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()

request = urllib.request.Request(
    f"{base}/api/v1/agents/me/runs",
    data=body,
    headers={
        "content-type": "application/json",
        "authorization": f"Bearer {token}",
        "x-cybernorf-timestamp": ts,
        "x-cybernorf-signature": sig,
    },
)
urllib.request.urlopen(request, timeout=30)
```

The body must be signed before it is sent and must not be re-serialized afterwards, since JSON key order and spacing are part of the signature.

### Demo flow

1. Sign in as the organization owner and open `/app/:orgSlug/agents`.
2. Register `builtin-monitor` with source `BUILTIN`; the page reveals the token exactly once.
3. Run the monitor with that token and refresh; the run appears with its pass/fail/skip breakdown and any new findings.
4. Register an `ANTHROPIC` agent: it stays `PENDING_APPROVAL` with no credential.
5. Approve it as the owner (optionally narrowing scopes) and copy the token from the reveal; then suspend, resume, and revoke it from the detail page.
6. Adopt a framework, then map the failing check on the agent page to a control; run the monitor again and open the control to see the evidence filed by the agent.
7. On `/app/:orgSlug/settings`, add an alert destination pointing at a receiver that prints the signature headers, send a test, then set the agent's expected interval to 5 minutes, stop running the monitor, and watch the sweep raise `AGENT_OFFLINE` (see below).
8. Rotate the builtin agent's token from the detail page, copy the new value into `CYBERNORF_AGENT_TOKEN`, and run the monitor again: the run is accepted and the old token returns 401.
9. Open `/app/:orgSlug/advisories`, insert the sample entry, and run the monitor again: the installed package appears under **Software inventory** on the agent page with the matching identifier, and the findings list gains `<package> <version> is affected by <identifier>` linked to the host asset.
10. Run `npm run data:retention -- --org :orgSlug --days 30` for a dry run, then add `--apply`; the audit page gains a `retention.purged` entry with the counts. Run `npm run data:export -- --org :orgSlug --out /tmp/:orgSlug.json` and confirm the file holds findings and the audit chain but no agent token material.

## Data retention and export

Two operator-run scripts cover the data lifecycle. Both load `.env`, so they talk to whatever database that file names; run them from a host that can reach Postgres.

| Command                                                           | Effect                                                                    |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `npm run data:retention -- --days 90`                             | Dry run: prints what a 90-day policy would remove, for every organization |
| `npm run data:retention -- --org acme --days 90 --apply`          | Deletes that history for one organization and appends `retention.purged`  |
| `npm run data:retention -- --days 90 --apply --prune-rate-limits` | Also removes rate-limit windows untouched for 24 hours                    |
| `npm run data:export -- --org acme --out acme.json`               | Writes one organization's records to a JSON file (mode `0600`)            |

`--org` accepts a slug or an id. Retention is deliberately narrow: it removes **agent runs**, **terminal alert deliveries** (`SENT` or `FAILED`; a `PENDING` row is never touched), and **package snapshots** whose `lastSeenAt` is older than the cutoff, which only happens when the agent stopped reporting. Findings, incidents, assets, compliance evidence, and the audit trail are business records and are never removed by a timer; a person closes them. Deleting a finding from the console still cascades to its `ControlEvidence` rows, so export before a cleanup if that evidence is part of an audit story.

The audit trail is append-only by trigger, so retention history itself is not trimmed: a purge adds one `retention.purged` event (actor `SYSTEM`, no user id) with the cutoff, the day count, and the exact number of rows removed. That is the answer to "where did last quarter's runs go".

The export is a single JSON document (`meta.format = "cybernorf.export"`, version `1`) with members, assets, findings, incidents and notes, compliance frameworks, controls, evidence, check mappings, agents (without credentials), runs, advisories, package snapshots, alert destinations (without secrets), deliveries, and the full audit chain with its hashes. It contains no token hashes, token prefixes, sealed webhook secrets, sessions, password hashes, or second-factor secrets — an export is a file that travels, so it is safe to hand to the organization that owns the data. Verify a returned file's chain by checking `prevHash`/`hash` in `sequence` order.

Neither script is scheduled for you; wrap them in cron or a systemd timer. A dry run first is the norm, and the export is the backup step before any purge.

After adding a migration, apply it to the test database before running the suite:

```sh
set -a && . ./.env.test && set +a && npx prisma migrate deploy
```

## Runtime audit

`scripts/audit-runtime.mjs` drives a running server over HTTP with real accounts and TOTP enrolment, and checks behavior that unit tests cannot observe: CSRF origin and `Sec-Fetch-Site` rejection, tenant isolation on reads and writes, uniform error shapes with `X-Request-Id`, content-type and body-size limits, per-user rate limiting with `Retry-After`, import races, page rendering with hostile filter values, and audit chain integrity after concurrent writes. It creates its own organizations and users, so point it at a development database only.

```sh
npm run dev          # in one shell
npm run audit:runtime   # in another; BASE_URL overrides http://localhost:3000
```

Sign-up is rate limited per address (5/min), so the script waits out a `429` instead of failing; back-to-back runs may pause for up to a minute. The same audit runs in CI against a production build.

## Checks

```sh
npm run format:check
npm run lint
npm run typecheck
npm test
npm run audit:runtime
npm run build
```

The GitHub Actions workflow provisions PostgreSQL, applies migrations to both the primary and test databases, runs these checks, starts a production build to run the runtime audit, audits npm dependencies at `high`, and scans repository history for secrets.

## Start the application

```sh
npm run dev
```

Open [http://localhost:3000](http://localhost:3000), then:

1. Create an account at `/sign-up` (password: 12+ characters). You land on `/app`.
2. If you have no organization yet, create one. You become its `OWNER`.
3. Open `/account/security` and enroll a TOTP authenticator. `OWNER` and `ADMIN` memberships are refused `403 MFA_REQUIRED` on every mutating request until a second factor is enabled, so enroll before creating data. Save the backup codes.
4. In the organization, register an asset, create a finding, move it through `OPEN → TRIAGED → IN_PROGRESS → RESOLVED`, then open `/app/<org>/audit` and verify the chain.
5. Add a second account as `VIEWER` from `members` to confirm that read-only access still sees the audit trail but cannot change records.

Liveness and readiness endpoints: `/api/health` returns `{"status":"ok"}` while the process serves requests; `/api/ready` also checks the database connection.

For a production build and local production server:

```sh
npm run build
npm run start
```

The build requires `BETTER_AUTH_SECRET` to be a valid 32+ character value when `NODE_ENV=production`, so provide it in the environment or `.env` before building. A local production server on `localhost`/`127.0.0.1` is accepted over http; a production host must use https and gets `308` redirects for plain-http requests (see [Transport security in production](#transport-security-in-production)).

## Troubleshooting

| Symptom                                              | Likely cause and fix                                                                                                                                                                                |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `docker compose up` fails: port already allocated    | Another PostgreSQL is running on 5432. Set `POSTGRES_HOST_PORT` to a free port and update `DATABASE_URL`.                                                                                           |
| Prisma `P1001`                                       | Wrong host or port. Try `127.0.0.1` instead of `localhost`; check `docker compose ps`.                                                                                                              |
| Tests abort with "refusing to run against ..."       | `DATABASE_URL` in `.env.test` does not point at a database whose name contains `test`.                                                                                                              |
| `403 MFA_REQUIRED` on every create/update            | The signed-in `OWNER` or `ADMIN` has not enrolled TOTP. Open `/account/security`.                                                                                                                   |
| `403 Cross-site requests are not allowed`            | `BETTER_AUTH_URL` does not match the origin in the browser address bar.                                                                                                                             |
| Production start logs `Failed to prepare server`     | `BETTER_AUTH_URL` is not `https://` for a non-loopback host, or `DATABASE_URL` points at a remote database without `sslmode`. Fix the URL, not the check.                                           |
| Prisma "Failed to deserialize column of type 'void'" | A raw query selected a `void` function result. Wrap advisory-lock calls in a subquery that returns a normal column.                                                                                 |
| Agent run rejected with `401`                        | The body does not match its signature, or the timestamp is more than five minutes off. Let the host clock sync, and sign the exact bytes that are sent.                                             |
| Every agent run rejected after rotation              | The host still holds the previous token. Copy the new one into `CYBERNORF_AGENT_TOKEN`.                                                                                                             |
| An advisory matches no host                          | The ecosystem must be identical and the name must match the reported spelling; the version must fall inside `affectedRange`. Import does not scan retroactively: run the monitor on the host again. |
| `422` importing advisories                           | The body must be `{ "advisories": [...] }` with `identifier`, `packageName`, `ecosystem`, `summary`, `severity`, and a readable `affectedRange`; the console page also accepts a bare array.        |
| Audit verification reports `hash_mismatch`           | An audit row changed outside the application. The trigger blocks the normal path, so investigate direct database access; do not "repair" the row.                                                   |
