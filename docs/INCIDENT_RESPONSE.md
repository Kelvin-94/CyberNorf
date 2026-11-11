# Monitoring, alerting and incident response

This is the operating playbook for the shipped deployment: one host, one console
container, one PostgreSQL database, one evidence volume ([DEPLOYMENT.md](DEPLOYMENT.md)).
It says what is watched, how a human is told, and what to do for each class of failure.

The product does not ship a pager. It ships signals with exit codes and endpoints that an
external monitor can page on; wiring that monitor is part of the deployment, and a
deployment without one has no alerting no matter what this document says.

## Detection sources

| Signal | What it proves | How to read it | Suggested schedule |
| --- | --- | --- | --- |
| `GET /api/health` | The process answers HTTP. Never touches the database. | `curl -fsS https://<host>/api/health` | every minute from outside the host |
| `GET /api/ready` | Database reachable **and** applied migrations match the image. `503` otherwise. | `curl -fsS https://<host>/api/ready` | every minute from outside the host |
| `npm run evidence:verify -- --all` | Every stored evidence blob still hashes to its recorded SHA-256. Any `MISMATCH` or `MISSING` exits `1`. A deployment with no `EVIDENCE_DIR` and no stored files exits `0` with a skip message; if stored files exist while `EVIDENCE_DIR` is unset it exits `1`, because those files cannot be verified. | Run in the container; non-zero is the alert. | daily |
| `npm run db:restore-drill` | A dump restores, every audit chain verifies, append-only triggers still reject writes. | JSON report on stdout; keep it as the drill record. | monthly, and before every upgrade |
| `GET /api/v1/organizations/[orgSlug]/audit/verify` | The tenant's audit chain verifies end to end. | Authenticated request; a break is reported, not thrown away. | weekly per tenant, or on suspicion |
| `npm run config:check` | The environment is valid and no security control was silently downgraded. | Non-zero exit on error. | before every deploy and after any env change |
| `server.started` log line | The app started, with feature booleans and the configuration fingerprint status. | `docker compose logs app \| grep server.started` | on every start |
| `config.changed` log line | The effective configuration differs from the last recorded digest. | `docker compose logs app \| grep config.changed` | on every start; a surprise is an incident lead |
| `config.invalid` / `config.warning` | Startup refused a broken environment, or accepted one with a warning. | Same log stream. | on every start |
| `request.unhandled_error` | A request failed outside the error mapper; carries `requestId`. | Same log stream. | continuous, triage daily |
| Notification delivery records | Alerts the product tried to send, with attempts and last error. | `notification_events` where `status` is `PENDING`/`FAILED`, or the channel's `lastError`. | daily |
| Capacity | Database size, evidence volume usage, backup age. | `docker system df`, `du -sh $EVIDENCE_DIR`, backup timestamps. | daily |

The host itself dying is the one failure the product cannot report, because the reporter
is the thing that died. That is what the external probe is for: point it at `/api/health`
and `/api/ready` from a different machine and page after three consecutive failures.

## Alert routing

There is no built-in routing. A working setup has three layers, and all three are the
operator's:

1. **External probe → pager.** Uptime service or a second host runs the two `curl`s above
   and pages the on-call person. This is the only layer that survives host loss.
2. **Cron → ticket or chat.** The daily `evidence:verify` and weekly audit verification
   run from cron; a non-zero exit posts to the same channel the pager uses.
3. **In-product webhooks → the tenant's own receiver.** Alert delivery for agent health and
   advisory matches is configured per tenant, signed, and retried. It is not a substitute
   for (1): it cannot report that the product is down.

Record the probe URL, the pager route and the cron entries in the deployment runbook. An
alert that only exists in someone's memory is not monitoring.

## Severity

| Level | Definition | Response |
| --- | --- | --- |
| SEV1 | Data loss or corruption, cross-tenant access, credential compromise, or the console is down for all users | Page immediately, all hands, customer communication within 24 hours |
| SEV2 | A core workflow is broken for one tenant (alerts not delivered, evidence unreadable) or a security control is degraded | Page in hours, fix same day, communicate to the affected tenant |
| SEV3 | Partial degradation, single feature, workaround exists | Next business day |
| SEV4 | Cosmetic or documentation defect | Normal backlog |

Roles in a one-person operation collapse into one person: incident lead, operator and
scribe are the same human. Write the timeline as you go anyway — the audit trail and the
logs will not reconstruct *why* a decision was made.

## Playbooks

### P1 — The console is unreachable

1. Confirm from outside: `curl -fsS https://<host>/api/health` and `/api/ready`. A `503`
   from `/api/ready` with `/api/health` healthy means database or migration, not the proxy.
2. Check the containers: `docker compose -f compose.prod.yaml ps` and
   `docker compose -f compose.prod.yaml logs --tail 200 app proxy database`.
3. `config.invalid` in the log means the app refused its environment; fix the variable, do
   not bypass the check.
4. If the host is down, the external probe has already paged. Recover the host, then the
   stack, then run the post-recovery checks below.
5. Record the outage window; if it exceeds the communicated target, send a notice.

### P2 — Database unavailable, migration failed, or restore needed

1. `/api/ready` `503` with a migration mismatch means the image is ahead of the schema:
   run `npm run db:migrate:deploy` from the image, never edit applied migrations.
2. A failed migration leaves the database in a partial state; stop the app first so no
   writes race the repair, and keep the pre-upgrade dump.
3. To restore: stop the app, restore the dump, restore `EVIDENCE_DIR` **with it**, start the
   app, then run `npm run db:restore-drill` — a drill report is the proof the restore is
   complete and the audit chains still verify.
4. A restored database without its evidence volume reports every file as `MISSING`. That is
   the designed behaviour, not a second failure; restore the volume before investigating.

### P3 — Evidence integrity failure (`MISMATCH` or `MISSING`)

1. `npm run evidence:verify -- --org <slug> --all` to scope it to one tenant.
2. `MISSING` means the row exists and the blob does not: check whether a restore, a volume
   resize or a manual cleanup removed it. It is a finding to explain, not automatically an
   intrusion.
3. `MISMATCH` means the bytes changed after upload. Treat it as SEV1 until explained:
   preserve the file (`cp` it aside before anything rewrites it), check who has volume
   access, and check the audit trail for deletions or restores around the file's
   `createdAt`.
4. The per-file verification route records an audit event; use it so the investigation
   itself is in the chain.
5. Do not delete the row to make the sweep green.

### P4 — Suspected secret compromise

1. Identify which secret: session/auth key, cron secret, OIDC client secret, database
   password, or a tenant credential (API key, agent token, machine credential, webhook
   signing key).
2. Rotate with the procedure in [SECRETS.md](SECRETS.md). Use
   `npm run secrets:rotate -- --name <VAR> --dir <SECRETS_DIR> --apply` for the three
   allow-listed values; it refuses to overwrite without `--force`, never prints the value,
   and writes atomically with mode `0600`.
3. Rotating `BETTER_AUTH_SECRET` invalidates every session, makes stored TOTP secrets
   unreadable and breaks sealed webhook secrets: plan the lockout and the re-enrollment,
   do not do it casually mid-day.
4. Tenant credentials are revoked through the product: personal API keys on
   `/account/security`, agent tokens by rotating the agent, machine credentials by rotating
   the identity credential, webhook secrets by recreating the channel.
5. Search the logs and audit trail for use of the old credential before and after
   rotation; record the window in the incident.

### P5 — Suspected authorization or cross-tenant defect

1. Preserve the request: method, URL, session or credential used (redacted in the record),
   response, and time.
2. Check `tests/tenant-isolation.test.ts` and the capability matrix in
   `src/server/authz/roles.ts`; a defect here is a missing scope predicate or a capability
   bound to the wrong method.
3. Treat as SEV1: revoke the credential, disable the affected membership, and export the
   tenant's audit chain before changing code so the evidence is not overwritten.
4. Fix, add a regression test that fails without the fix, then re-run the full suite and
   the API review in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).

### P6 — Alerts are not being delivered

1. Is `CRON_SECRET` set and is the scheduler calling `GET /api/cron/notifications`? An
   unset secret makes the route answer `503` and nothing is swept.
2. Inspect `notification_events`: `PENDING` with `attempts` climbing means the receiver is
   failing; `FAILED` with `lastError` names the reason (DNS, TLS, timeout, non-2xx).
3. `NOTIFY_ALLOW_PRIVATE_WEBHOOKS=false` refuses a receiver that resolves to a private
   address; that is the SSRF guard, not a bug.
4. A stuck `PENDING` row with `nextAttemptAt` far in the future is backoff working; do not
   force it unless the incident needs the alert delivered now.

### P7 — Account compromise or lockout

1. Compromised account: end its sessions, disable the membership, rotate its API keys, and
   review `auth_events` and the tenant audit trail for actions taken.
2. Locked-out owner: recovery is a database operation with operator credentials; there is
   no self-service owner reset. Record it in the audit trail afterwards.
3. Lost second factor: use a backup code; if those are gone, the account recovery is an
   operator procedure, not an email link.

### P8 — Disk full or quota exhausted

1. `EVIDENCE_DIR` full: uploads fail with a server error; free space or grow the volume,
   then re-run the integrity sweep. Never delete blobs that rows still reference.
2. Database full: check table sizes first; `agent_runs` and `software_items` are the tables
   retention is allowed to purge (`npm run data:retention` dry-run first).
3. Quota exhausted for a tenant: `npm run quota -- show <slug>` shows limits and usage;
   `npm run quota -- set <slug> <resource> <limit\|none> --apply` raises it (without
   `--apply` it prints the intended change and stops). The change is an operator action,
   not tenant self-service, and it is written to the tenant audit chain.

## After any incident

1. Verify: `/api/ready` green, `evidence:verify` clean for the affected tenant, audit chain
   verifies, alerts deliver a test message.
2. Write the timeline from logs, audit events and notes; keep the export or drill report
   that proves the final state.
3. Record the follow-up work with an owner and a date. An incident without a follow-up is a
   rehearsed outage.
4. If customer data was exposed, follow the advisory process in
   [DEPENDENCY_RESPONSE.md](DEPENDENCY_RESPONSE.md#customer-advisories) — the same
   communication path is used for vulnerability and incident notices.

## Known gaps

- No built-in pager, no log shipping, no metrics endpoint: detection depends on an external
  probe plus log reading on the host.
- One host means host loss is a full outage; there is no failover and no measured RTO/RPO.
- Alert delivery is at-least-once with bounded retries; a receiver that is down longer than
  the retry window loses the alert, and the delivery record is the only trace.
- The playbooks have not been exercised in a real incident. The restore drill is the only
  rehearsed procedure; a tabletop for P3/P4/P5 is still to be run and dated.
