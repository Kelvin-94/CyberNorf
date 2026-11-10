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

2. Build and start:

   ```sh
   docker compose -f compose.prod.yaml --env-file .env.production up -d --build
   ```

   The order is database (healthy) → migrations (exit 0) → app (healthy) → proxy.

3. Confirm the deployment:

   ```sh
   docker compose -f compose.prod.yaml --env-file .env.production ps
   curl -sS https://cybernorf.example.com/api/health   # {"status":"ok"}
   curl -sS https://cybernorf.example.com/api/ready    # {"status":"ready",...}

   # Plain http must redirect, and the app must answer with HSTS.
   curl -sSI http://cybernorf.example.com/ | head -3
   curl -sSI https://cybernorf.example.com/sign-in | grep -i strict-transport-security
   ```

4. Create the first account at `/sign-up`, enrol a TOTP authenticator on `/account/security`, then create the organization. `OWNER` and `ADMIN` memberships are refused every mutation until a second factor exists.

## Operating it

**Logs.** `docker compose -f compose.prod.yaml logs -f app proxy`. The proxy logs one JSON line per request and never records `Authorization` or `Cookie` headers.

**Backups.** Two volumes matter: `cybernorf-prod_database-data` and `cybernorf-prod_caddy-data` (the latter holds the ACME account key and certificates, so losing it means re-issuing).

```sh
docker compose -f compose.prod.yaml exec -T database \
  pg_dump -U cybernorf -d cybernorf --format=custom > "cybernorf-$(date +%F).dump"
```

Restore into a fresh volume with `pg_restore --clean --if-exists`. Take a dump before every upgrade; migrations are forward-only.

**Application-level export.** `npm run data:export -- --org <slug> --out <file>` writes one tenant's records with a credential-free audit chain. Run it from a checkout that can reach the database, or through the API with a personal key.

**Scheduled alert sweep.** The platform ships no worker, so a timer calls the cron route:

```cron
*/10 * * * * curl -fsS -H "Authorization: Bearer $CRON_SECRET" https://cybernorf.example.com/api/cron/notifications >/dev/null
```

**Retention.** `npm run data:retention -- --days 90 --apply` prunes agent runs, delivered alerts and stale package snapshots. Run it dry first, and export before it runs.

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

## Managed database instead of the bundled one

Point `DATABASE_URL` at the provider's host with `sslmode=verify-full` and `sslrootcert` set to their CA bundle, then remove the `database` service and the `database-tls` mounts from `app` and `migrate`. The app's startup check requires TLS for any non-loopback database host, so it will refuse to boot on a plaintext connection.

## Troubleshooting

| Symptom                                     | Cause and fix                                                                                                                                       |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `proxy` restarts, log shows ACME failures   | DNS does not resolve to this host, or port 80/443 is blocked. Caddy retries; fix reachability rather than disabling TLS.                            |
| App logs `Failed to prepare server`         | `BETTER_AUTH_URL` is not `https://`, or `DATABASE_URL` has no TLS mode. The message names the variable.                                             |
| `migrate` exits non-zero with `P1001`       | The database container is not healthy yet, or the password in `DATABASE_URL` differs from `POSTGRES_PASSWORD`.                                      |
| `migrate` fails with a certificate error    | The `database-tls` volume is empty because the database never started, or `sslrootcert` does not point at `/etc/cybernorf/database-tls/server.crt`. |
| `403 Cross-site requests are not allowed`   | `BETTER_AUTH_URL` differs from the origin in the address bar (scheme, host or port).                                                                |
| `app` reports unhealthy but serves requests | Readiness also checks the database; look at the `database` container's health and `pg_stat_activity`.                                               |
| Certificate issued for the wrong name       | `CYBERNORF_DOMAIN` and the DNS record disagree. Remove the `caddy-data` volume after fixing it, so Caddy re-issues.                                 |
