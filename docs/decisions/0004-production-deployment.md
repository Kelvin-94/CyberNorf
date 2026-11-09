# ADR 0004: Single-host production deployment with a TLS proxy

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

The application enforces two transport rules at startup: `BETTER_AUTH_URL` must be an `https://` origin outside loopback, and a non-loopback `DATABASE_URL` must request TLS (`src/server/config.ts`). Those rules are only useful if a deployment can actually satisfy them. Until now the repository shipped one compose file that ran PostgreSQL for development; there was no supported way to run the console behind TLS, apply migrations on deploy, or keep the database off the network.

Whoever deploys this is a small team running one host, not a platform group. The deployment therefore has to be reproducible from the repository alone, has to fail closed when a secret is missing, and must not require a certificate workflow the operator has to babysit.

## Decision

- **One compose file, four services.** `compose.prod.yaml` defines `database`, a one-shot `migrate`, `app`, and `proxy`. Only the proxy publishes ports (80 and 443). The app is reachable only on the `edge` network, and the database only on `backend`, which is `internal`.
- **Caddy as the TLS terminator.** Caddy obtains and renews the certificate for `CYBERNORF_DOMAIN` over ACME and forwards `X-Forwarded-Proto: https`. The application's existing reverse-proxy guard (`src/proxy.ts`) redirects any request that arrives without that header, so a misconfigured proxy fails closed instead of serving sessions over cleartext. nginx plus certbot was rejected for the extra moving parts (renewal hooks, reload coordination); the Caddyfile is a dozen lines an operator can read.
- **Migrations from the same image that serves traffic.** The `migrate` service runs `npx prisma migrate deploy` from the `runner` image and the app waits for it with `service_completed_successfully`. Code and schema cannot be deployed out of step. The cost is that the runtime image keeps dev dependencies, because the Prisma CLI is one of them; the image is about 1.6 GB.
- **Verified TLS to the database.** The database's entrypoint wrapper generates a self-signed certificate on first boot into its own volume. That volume is mounted read-only into the app and migration containers, and `DATABASE_URL` carries `sslmode=verify-full&sslrootcert=/etc/cybernorf/database-tls/server.crt`. Current `pg` releases treat `sslmode=require` as `verify-full` anyway, so pinning the CA is the honest configuration rather than a weaker one with a surprising failure mode.
- **Narrow blast radius for the app container.** It runs as the unprivileged `node` user with a read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, and tmpfs for `/tmp` and the Next.js cache. The server compiles nothing at runtime, so this costs nothing.
- **No placeholder can boot.** Every required value uses compose's `${VAR:?message}` form, and `.env.production.example` documents what each one is for. A missing secret stops the start instead of silently using a default.
- **Security headers stay in the application.** CSP, HSTS, `X-Frame-Options`, COOP and Permissions-Policy are emitted by `next.config.ts`, so they also apply when the app is fronted by something other than this proxy. The proxy only strips `Server`.

## Consequences

- The reference deployment is one host. There is no high availability, no blue/green switch, and no horizontal scaling. Sessions, rate limits and audit writes already live in PostgreSQL, so running several `app` containers behind the proxy is possible, but it is untested and deliberately undocumented as supported.
- ACME requires a public DNS record and reachable ports 80 and 443. An air-gapped installation has to supply its own certificate; the compose file does not pretend otherwise.
- The generated database certificate is valid for ten years and tied to the `database-tls` volume. Replacing it means regenerating the volume contents and restarting both the database and the app; a managed database with a provider CA bundle is the documented alternative.
- The image is built locally from the repository. There is no published registry image, no SBOM, and no image signing yet; an operator who needs those has to add them.
- Rollback is "check out the previous commit and redeploy". Migrations are forward-only, so a rollback that crosses a schema change requires restoring the dump taken before the upgrade.
- Copying the Caddyfile's `trusted_proxies` and ACME settings is not a substitute for review: changing `CYBERNORF_DOMAIN` without changing the DNS record produces a certificate for the wrong name, which is why the operator steps are written down in [DEPLOYMENT.md](../DEPLOYMENT.md).
