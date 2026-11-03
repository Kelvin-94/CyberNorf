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

| Variable             | Required                | Purpose                                                                          |
| -------------------- | ----------------------- | -------------------------------------------------------------------------------- |
| `DATABASE_URL`       | yes                     | PostgreSQL connection string used by Prisma and the app.                         |
| `BETTER_AUTH_SECRET` | yes outside development | Signs sessions and encrypts second-factor secrets. 32+ characters in production. |
| `BETTER_AUTH_URL`    | yes                     | Public origin. Used for cookies, trusted origins, and the same-origin check.     |
| `POSTGRES_HOST_PORT` | Compose only            | Host port mapped to the PostgreSQL container.                                    |

If Prisma reports `P1001: Can't reach database server` while `nc -z 127.0.0.1 <port>` succeeds, replace `localhost` with `127.0.0.1` in the connection string. Some macOS setups resolve `localhost` to IPv6 first, where the container is not listening.

## Database and migrations

The Phase 1 schema and its migrations are checked in:

- `20261102114540_phase1_soc_foundation` — identity, organizations, assets, findings, incidents, and audit tables.
- `20261102114550_audit_append_only_guard` — the trigger that rejects `UPDATE` and `DELETE` on `audit_events`.
- `20261102115532_organization_description` — organization descriptions.

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
- `tests/tenant-isolation.test.ts` — cross-tenant reads, writes, relationship abuse, disabled memberships, and MFA enforcement.
- `tests/audit-integrity.test.ts` — every mutation appends a linked event, rows cannot be updated or deleted, chains stay valid per organization.
- `tests/findings-workflow.test.ts` — the acceptance workflow and import deduplication.
- `tests/rate-limit.test.ts` — window accounting and `429` behavior.
- `tests/regression-defects.test.ts` — defects found by the runtime audit, kept as regressions: in-payload duplicate imports, concurrent import races, fingerprint stability across renames and asset deletion, session revocation scope on membership removal, active-only member counts, slug collisions, and case-insensitive member lookup.

The database-backed suites rely on `TRUNCATE ... RESTART IDENTITY CASCADE` rather than row deletes, because `audit_events` rejects `DELETE` at the trigger level.

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

The build requires `BETTER_AUTH_SECRET` to be a valid 32+ character value when `NODE_ENV=production`, so provide it in the environment or `.env` before building.

## Troubleshooting

| Symptom                                              | Likely cause and fix                                                                                                                              |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `docker compose up` fails: port already allocated    | Another PostgreSQL is running on 5432. Set `POSTGRES_HOST_PORT` to a free port and update `DATABASE_URL`.                                         |
| Prisma `P1001`                                       | Wrong host or port. Try `127.0.0.1` instead of `localhost`; check `docker compose ps`.                                                            |
| Tests abort with "refusing to run against ..."       | `DATABASE_URL` in `.env.test` does not point at a database whose name contains `test`.                                                            |
| `403 MFA_REQUIRED` on every create/update            | The signed-in `OWNER` or `ADMIN` has not enrolled TOTP. Open `/account/security`.                                                                 |
| `403 Cross-site requests are not allowed`            | `BETTER_AUTH_URL` does not match the origin in the browser address bar.                                                                           |
| Prisma "Failed to deserialize column of type 'void'" | A raw query selected a `void` function result. Wrap advisory-lock calls in a subquery that returns a normal column.                               |
| Audit verification reports `hash_mismatch`           | An audit row changed outside the application. The trigger blocks the normal path, so investigate direct database access; do not "repair" the row. |
