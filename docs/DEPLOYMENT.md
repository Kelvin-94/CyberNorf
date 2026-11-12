# Production deployment

This guide deploys the console on one Linux host with Docker Compose. The stack is `compose.prod.yaml`: a Caddy reverse proxy that terminates TLS, the Next.js server, and PostgreSQL. Only the proxy publishes ports.

For local development see [DEVELOPMENT.md](DEVELOPMENT.md); for the design and its limits see [ARCHITECTURE.md](ARCHITECTURE.md).

## What the stack establishes

| Property                                            | How                                                                                                                                                                     |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TLS on the public edge                              | Caddy obtains and renews a certificate for `CYBERNORF_DOMAIN` over ACME. HTTP requests reach the app only after the proxy has terminated TLS.                           |
| The app is never published                          | `app` has no `ports:` entry. It listens on the compose `edge` network, where only the proxy can reach it.                                                               |
| Clear-text requests do not reach a session          | The app redirects anything without `x-forwarded-proto: https` with `308`, except on loopback. The proxy always sets that header.                                        |
| The database is not reachable from the LAN          | `database` publishes nothing and sits on the `backend` network, which is `internal`.                                                                                    |
| Database traffic is encrypted and verified          | The database generates a certificate on first boot, and `DATABASE_URL` carries `sslmode=verify-full&sslrootcert=…` pointing at the read-only copy mounted into the app. |
| A compromised app process has a narrow blast radius | The container runs as the unprivileged `node` user, with a read-only root filesystem, `cap_drop: ALL` and `no-new-privileges`.                                          |
| The schema in use matches the code                  | The one-shot `migrate` service applies migrations from the same image the app runs, and the app waits for it to finish.                                                 |
| No placeholder secret can boot                      | Every required value uses compose's `:?` form, so a missing or empty value stops the start instead of defaulting.                                                       |

The app sends its own security headers (CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, COOP, Permissions-Policy), so the proxy only strips `Server`.

## Prerequisites

- A Linux host with Docker Engine 27+ and Compose v2.24+.
- A DNS `A`/`AAAA` record for `CYBERNORF_DOMAIN` pointing at the host.
- Ports 80 and 443 reachable from the internet, because ACME validates over HTTP and the console is served over HTTPS.
- About 2 GB of RAM. The image is roughly 1.6 GB because it carries the Prisma CLI that applies migrations.

## First deployment

1. Create the environment file and fill in every value:

   ```sh
   cp .env.production.example .env.production
   chmod 600 .env.production
   ```

   | Variable             | Notes                                                                                                         |
   | -------------------- | ------------------------------------------------------------------------------------------------------------- |
   | `CYBERNORF_DOMAIN`   | Public hostname. Must match the DNS record.                                                                   |
   | `ACME_EMAIL`         | Contact address the certificate authority uses for expiry notices.                                            |
   | `BETTER_AUTH_URL`    | `https://` plus the same hostname. The app compares it to the request origin on every state-changing request. |
   | `BETTER_AUTH_SECRET` | `openssl rand -base64 48`. At least 32 characters.                                                            |
   | `CRON_SECRET`        | `openssl rand -base64 32`. Empty disables the alert sweep.                                                    |
   | `POSTGRES_PASSWORD`  | Used when the volume is created.                                                                              |
   | `DATABASE_URL`       | Must repeat that password and keep `sslmode=verify-full&sslrootcert=/etc/cybernorf/database-tls/server.crt`.  |

2. Check the configuration before starting anything. This loads the same file the
   stack will use, reports every problem at once, names variables but never
   prints values, and exits non-zero if the app would refuse to boot or would
   quietly disable a control:

   ```sh
   npm run config:check -- --env-file .env.production
   ```

3. Build and start:

   ```sh
   docker compose -f compose.prod.yaml --env-file .env.production up -d --build
   ```

   The order is database (healthy) → migrations (exit 0) → app (healthy) → proxy.

4. Confirm the deployment:

   ```sh
   docker compose -f compose.prod.yaml --env-file .env.production ps
   curl -sS https://cybernorf.example.com/api/health   # {"status":"ok"}
   curl -sS https://cybernorf.example.com/api/ready    # {"status":"ready",...}

   # Plain http must redirect, and the app must answer with HSTS.
   curl -sSI http://cybernorf.example.com/ | head -3
   curl -sSI https://cybernorf.example.com/sign-in | grep -i strict-transport-security
   ```

5. Create the first account at `/sign-up`, enrol a TOTP authenticator on `/account/security`, then create the organization. `OWNER` and `ADMIN` memberships are refused every mutation until a second factor exists.

## Operating it

**Logs.** `docker compose -f compose.prod.yaml logs -f app proxy`. The proxy logs one JSON line per request and never records `Authorization` or `Cookie` headers. The app also logs one JSON line per event to stdout — `server.started` at boot and `request.unhandled_error` for unexpected failures — controlled by `LOG_LEVEL` (default `info`). It logs no request bodies or headers, and every record is redacted before it is written; see [LOGGING.md](LOGGING.md). Bound the Docker log file with the `json-file` driver's `max-size`/`max-file` options, because neither stream rotates itself.

**Health probes.** Two endpoints serve different purposes and should not be confused:

| Endpoint      | Answers   | Checks                                                                                | Use it for                                                                                             |
| ------------- | --------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `/api/health` | liveness  | the process is running; never touches the database                                    | external uptime checks where a database blip must not trigger a restart                                |
| `/api/ready`  | readiness | the database answers, and the applied migrations match the ones shipped in this image | the container `HEALTHCHECK` (as in `compose.prod.yaml`), load balancer membership, drain, deploy gates |

`/api/ready` returns `503` with `checks.migrations` set to `pending` when the database is behind the image — the state that produces confusing runtime errors instead of a clean failure. `ahead` means the database carries migrations this image does not ship, which is what a rollback looks like; it is reported but does not fail readiness, because forward-only migrations are additive and refusing traffic would turn a rollback into an outage. Neither endpoint returns error text, migration names or connection details.

**External monitoring.** Nothing in the stack pages a human. Point an external monitor at `/api/ready` and alert on a non-200 response or on the container disappearing entirely, because a probe served by a dead process cannot report its own death:

```sh
# every minute, alert after three consecutive failures
curl -fsS https://cybernorf.example.com/api/ready >/dev/null || notify-on-call
```

Alert on the absence of a response as well as a failing one; use an outside-in service rather than a cron job on the same host, which fails silently when the host does.

**Backups.** Two volumes matter: `cybernorf-prod_database-data` and `cybernorf-prod_caddy-data` (the latter holds the ACME account key and certificates, so losing it means re-issuing).

```sh
docker compose -f compose.prod.yaml exec -T database \
  pg_dump -U cybernorf -d cybernorf --format=custom > "cybernorf-$(date +%F).dump"
```

Restore into a fresh volume with `pg_restore --clean --if-exists`. Take a dump before every upgrade; migrations are forward-only.

**Restore drill.** A dump that has never been restored is an assumption, not a control. The drill proves the archive restores and that the restored copy still enforces what the application depends on:

```sh
npm run db:restore-drill -- --docker-exec cybernorf-prod-database-1 --report "drill-$(date +%F).json"
```

Point `DATABASE_URL` at the database under test first. The script creates a throwaway `cybernorf_drill_*` database on the same server, dumps the source with `pg_dump`, restores it with `pg_restore --exit-on-error`, and then compares the two copies: table set, column definitions, constraints, triggers and migration history must match. It re-verifies every organization's audit chain with the application's own `verifyAuditChain`, and it attempts an `UPDATE` against `audit_events`, `auth_events` and `identity_events` to confirm the append-only triggers still reject writes after a restore. It exits non-zero on any failure, writes a JSON report suitable for retaining as evidence, and drops the throwaway database unless `--keep` is passed.

`--docker-exec <container>` runs `pg_dump` and `pg_restore` inside the database container, which is what the compose stack ships; omit it when the host has PostgreSQL 17 client tools and the server is reachable directly.

The drill creates and drops a database, so the connection needs `CREATEDB`. For the compose stack that is the `cybernorf` superuser already in `DATABASE_URL`.

If the drill reports `hash_mismatch` or `link_mismatch`, stop: the audit chain in the archive does not match its own hashes, which means the source was modified out of band or the dump is damaged. Do not restore that archive over production without investigating first.

The drill compares `CHECK` constraints by their sorted conjuncts rather than by raw text, because PostgreSQL re-parses a restored predicate and a logically identical definition can come back with different grouping. Predicates containing `OR`, `NOT`, `BETWEEN` or a subquery are compared exactly, where the grouping does matter.

**Availability and recovery targets.** The single-host stack targets the following, and the drill is the evidence that the restore path exists:

| Target                          | Value    | What has to be true                                                                                                                                                      |
| ------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Recovery time objective (RTO)   | 4 hours  | Rebuild the host, restore the latest dump into a fresh volume, run `migrate`, pass the restore drill, then return traffic.                                               |
| Recovery point objective (RPO)  | 24 hours | One `pg_dump` per day, stored outside the host. A dump kept only on the database volume is not a backup: losing the host loses it too.                                   |
| Drill duration, current dataset | 2.7 s    | Measured on 2026-11-12: 45 tables, 16 migrations, 177 constraints, 625 audit events recomputed. The report is archived as `docs/evidence/restore-drill-2026-11-12.json`. |

The measured duration is a development-size dataset, not production evidence: it shows the dump, restore and verification path works, not that a production database restores inside the RTO. Re-run the drill against a production-size copy before relying on the target, and record the result. A tighter RPO needs continuous archiving: PostgreSQL WAL archiving to object storage, or a managed database with point-in-time recovery, which replaces the daily dump in the table above.

**Application-level export.** `GET /api/v1/organizations/{slug}/export` downloads one tenant's records and audit chain as JSON behind the `export.download` capability, rate-limited to five requests per five minutes; `GET …/export/package` returns the signed package described above at three per five minutes. `npm run data:export -- --org <slug> --out <file>` remains the offline path for a checkout that can reach the database.

**Scheduled alert sweep.** The platform ships no worker, so a timer calls the cron route:

```cron
*/10 * * * * curl -fsS -H "Authorization: Bearer $CRON_SECRET" https://cybernorf.example.com/api/cron/notifications >/dev/null
15 2 * * * curl -fsS -H "Authorization: Bearer $CRON_SECRET" https://cybernorf.example.com/api/cron/retention >/dev/null
```

The second timer applies each tenant's saved retention policy. It is safe to run more often than daily: an organization with nothing past its window is left untouched and writes no audit entry. An organization that never saved a policy is skipped entirely, so a default nobody confirmed never deletes records. The route answers `500` when any tenant's sweep failed and reports which ones, so a failing timer is visible instead of looking like a clean run.

**Retention.** Each tenant sets its own windows in the console under _Settings → Retention_, backed by `GET`/`PUT /api/v1/organizations/{slug}/settings/retention`, `GET …/retention/preview` and `POST …/retention/purge`. Reading needs `retention.read`; changing the policy needs OWNER or ADMIN; purging is OWNER-only and records the exact deleted counts in the audit chain. The console preview is read-only, and findings, incidents, evidence and the audit chain are outside the policy. For a one-off operator sweep there is also `npm run data:retention -- --days 90 --apply`, which prunes agent runs, delivered alerts and stale software inventory rows; run it dry first, and export before it runs.

**Upgrades.**

```sh
git pull
docker compose -f compose.prod.yaml --env-file .env.production up -d --build
```

The `migrate` service runs again before the new app container starts. To roll back, check out the previous commit and repeat; a migration that already ran is not reverted automatically, so restore the dump if the previous code cannot read the new schema.

**Stopping.** `docker compose -f compose.prod.yaml down` keeps the volumes. Adding `-v` deletes the database, the generated certificate and the ACME state.

## Single sign-on

The stack ships with password sign-in and can additionally delegate authentication to an OpenID Connect provider. Nothing changes in `compose.prod.yaml`: set the variables in `.env.production` and restart the app container.

1. At the provider, register a confidential web application with the redirect URI `https://<CYBERNORF_DOMAIN>/api/auth/callback/oidc` and the authorization-code grant with PKCE. It must return `email` and `email_verified` claims.
2. Fill in `.env.production`:

   ```sh
   OIDC_ISSUER=https://idp.example.com
   OIDC_CLIENT_ID=cybernorf
   OIDC_CLIENT_SECRET=...
   OIDC_DISPLAY_NAME="Acme SSO"     # optional, button label
   ```

3. `docker compose -f compose.prod.yaml --env-file .env.production up -d app` and confirm the sign-in page shows "Continue with Acme SSO" next to the password form.

Notes that matter during an incident:

- Set all three of `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`, or none. A partial set stops the app at startup instead of serving a login method the operator did not intend.
- Discovery (`<issuer>/.well-known/openid-configuration`) is fetched by the app, so the container needs egress to the provider. The `edge` network the app shares with the proxy provides it; the `backend` network stays internal. The fetch is bounded to five seconds at startup and on the sign-in retry, so an unresponsive provider cannot hang the first request: if it is down when the app starts, SSO is unavailable until the next sign-in attempt retries discovery, and passwords still work.
- An IdP user whose verified email matches an existing CyberNorf account is signed in as that account, with its existing memberships. Unverified addresses are refused, and no role or organization is ever taken from a token claim.
- Removing a user from the provider does not remove the CyberNorf account or its sessions. Deactivate the membership in the console as well.

## Data residency and subprocessors

CyberNorf runs entirely on infrastructure the operator chooses: one application container and one PostgreSQL database, with no vendor-operated control plane, no telemetry and no licence check. Tenant records — assets, findings, incidents, identities, evidence, retention policies and the append-only audit chains — live in that database and in the volumes `compose.prod.yaml` mounts. The data region is therefore the region of the host and of the backups; nothing in the stack copies tenant data anywhere else.

The stack makes these outbound connections, and no others:

| Destination                                           | When                                                  | What leaves                                                                            | Can it be turned off                                                                                  |
| ----------------------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| ACME certificate authority (Let's Encrypt by default) | certificate issue and renewal                         | the public hostname and the `ACME_EMAIL` contact                                       | Yes. Terminate TLS on an upstream proxy or load balancer and serve the app over its internal network. |
| OpenID Connect provider                               | only when SSO is configured, at sign-in and discovery | the authorization request and the provider's own claims                                | Yes. Leave the `OIDC_*` variables unset and use password sign-in.                                     |
| Tenant-configured webhook endpoints                   | alert delivery, on a timer or a manual test           | event id and type, organization id, agent name/source, health and the observation time | Yes. Configure no alert destinations.                                                                 |
| Container registry                                    | image pull during deploy                              | no tenant data                                                                         | Yes. Mirror the image into a registry you control.                                                    |
| DNS resolver                                          | webhook hostname validation and execution dispatch    | the webhook hostname, or the engagement's target name                                  | The resolver is host configuration; point it at a resolver in your jurisdiction.                      |

**Subprocessors.** There are none by default: the operator runs the software and remains the controller of the data. Enabling SSO adds the identity provider as a subprocessor for authentication data, and configuring an alert destination adds that receiver as a subprocessor for the alert payload. Both are the operator's choice, configured per tenant, and both can be removed without touching the database.

**Data location controls.** Point `DATABASE_URL` at a managed database in the required region (see below), keep dumps in that region, and use `npm run data:export -- --org <slug>` for a portable copy. Deleting an organization cascades to its tenant rows; the audit trail of that deletion is retained, as the compliance record.

## Managed database instead of the bundled one

Point `DATABASE_URL` at the provider's host with `sslmode=verify-full` and `sslrootcert` set to their CA bundle, then remove the `database` service and the `database-tls` mounts from `app` and `migrate`. The app's startup check requires TLS for any non-loopback database host, so it will refuse to boot on a plaintext connection.

## Troubleshooting

| Symptom                                     | Cause and fix                                                                                                                                                                                                   |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `proxy` restarts, log shows ACME failures   | DNS does not resolve to this host, or port 80/443 is blocked. Caddy retries; fix reachability rather than disabling TLS.                                                                                        |
| App logs `Invalid configuration`            | Startup validation refused the environment. The report lists every failing variable and rule; run `npm run config:check -- --env-file .env.production` to iterate without restarting. Values are never printed. |
| `migrate` exits non-zero with `P1001`       | The database container is not healthy yet, or the password in `DATABASE_URL` differs from `POSTGRES_PASSWORD`.                                                                                                  |
| `migrate` fails with a certificate error    | The `database-tls` volume is empty because the database never started, or `sslrootcert` does not point at `/etc/cybernorf/database-tls/server.crt`.                                                             |
| `403 Cross-site requests are not allowed`   | `BETTER_AUTH_URL` differs from the origin in the address bar (scheme, host or port).                                                                                                                            |
| `app` reports unhealthy but serves requests | Readiness also checks the database; look at the `database` container's health and `pg_stat_activity`.                                                                                                           |
| Certificate issued for the wrong name       | `CYBERNORF_DOMAIN` and the DNS record disagree. Remove the `caddy-data` volume after fixing it, so Caddy re-issues.                                                                                             |
