# Secrets and configuration

What the deployment needs, what each value protects, what breaks when it
changes, and how to change it without an outage nobody expected. Every claim
below was checked against the code; the rotation consequences in particular are
pinned by tests, because guessing them is how a rotation becomes an incident.

- [Validation](#validation)
- [Secret inventory](#secret-inventory)
- [Rotating BETTER_AUTH_SECRET](#rotating-better_auth_secret)
- [Rotating CRON_SECRET](#rotating-cron_secret)
- [Rotating the database password](#rotating-the-database-password)
- [Rotating the identity-provider secret](#rotating-the-identity-provider-secret)
- [Rotating the package signing key](#rotating-the-package-signing-key)
- [Credentials issued inside the app](#credentials-issued-inside-the-app)
- [Mounted secret files](#mounted-secret-files)
- [Configuration fingerprint](#configuration-fingerprint)
- [Handling the environment file](#handling-the-environment-file)
- [Known gaps](#known-gaps)

## Validation

Two entry points, one implementation (`src/server/config/env.ts`):

| Command                                              | When                     | Behaviour                                                                 |
| ---------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------- |
| `npm run config:check`                               | before a deploy          | validates `.env` and exits `1` on any error                               |
| `npm run config:check -- --env-file .env.production` | before promoting a build | validates that file instead, with the shell environment taking precedence |
| app startup (`src/instrumentation.ts`)               | every boot               | throws on any error, so the process serves nothing but `500`s             |

The validator reports **every** problem at once rather than stopping at the
first, names the variable and the rule, and never prints a value. Errors stop
the app; warnings are logged as `config.warning` and allowed through, because
they describe intent rather than a broken deployment.

The rules it enforces:

| Variable                        | Rule                                                                                                | Severity        |
| ------------------------------- | --------------------------------------------------------------------------------------------------- | --------------- |
| `DATABASE_URL`                  | required, `postgresql://`, must name host and database                                              | error           |
| `BETTER_AUTH_URL`               | required, absolute, `https://` in production outside loopback                                       | error           |
| `BETTER_AUTH_SECRET`            | required in production, at least 32 characters                                                      | error           |
| `CRON_SECRET`                   | at least 24 characters if set; unset disables the sweep                                             | error / warning |
| `AGENT_REQUIRE_SIGNED_RUNS`     | exactly `true` or `false` if set                                                                    | error           |
| `NOTIFY_ALLOW_PRIVATE_WEBHOOKS` | exactly `true` or `false` if set; `true` in production warns                                        | error / warning |
| `OIDC_*`                        | all three of `OIDC_ISSUER`/`CLIENT_ID`/`CLIENT_SECRET`, or none; issuer `https://` outside loopback | error           |
| `SECRETS_DIR`                   | absolute path if set; each entry is validated when it is read                                       | error           |
| `EVIDENCE_DIR`                  | absolute path if set; unset means file evidence is unavailable, not broken                          | error           |
| `EVIDENCE_SIGNING_KEY`          | at least 32 characters if set; unset disables signed packages, and the route answers 503            | error           |
| `EVIDENCE_SIGNING_KEY_ID`       | 1–64 letters, digits, dot, dash or underscore if set; recorded in every manifest                    | error           |
| `NODE_ENV`                      | `development`, `test` or `production`; unset warns                                                  | warning         |
| `LOG_LEVEL`                     | `debug`, `info`, `warn` or `error`; unknown warns and falls back to `info`                          | warning         |

The boolean rules matter more than they look. The application compares these
variables to the literal string `'true'`, so `AGENT_REQUIRE_SIGNED_RUNS=1`
reads as **off** — a silent downgrade of a security control. The validator
refuses that instead of letting it boot.

## Secret inventory

| Variable                                      | What it protects                                                                              | If it leaks                                                                                                                                                  | Changing it invalidates                                                               |
| --------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `BETTER_AUTH_SECRET`                          | Signs session tokens; encrypts TOTP secrets and backup codes; derives the webhook sealing key | Forged sessions for any account: full takeover. Treat as total compromise.                                                                                   | **Every session**, every enrolled second factor, and every sealed webhook signing key |
| `DATABASE_URL`                                | The password inside it authenticates the app to PostgreSQL                                    | Direct read/write access to all tenant data and the audit trail                                                                                              | Nothing, once the database password is changed                                        |
| `CRON_SECRET`                                 | Bearer token for `POST /api/cron/notifications`                                               | Ability to trigger the alert sweep early. No data is returned.                                                                                               | Nothing; update the scheduler in the same step                                        |
| `OIDC_CLIENT_SECRET`                          | Authenticates CyberNorf to the identity provider                                              | An attacker who can also redirect the browser could attempt code interception; it does not grant access to CyberNorf by itself                               | Nothing; restart picks it up                                                          |
| `EVIDENCE_SIGNING_KEY`                        | Signs evidence-package manifests so a copy that left the platform can be checked              | Anyone holding it can produce a package that verifies. It grants no database access, so the exposure is forged or altered package evidence, not tenant data. | Every package issued with the old key must be verified with that key and its key id   |
| `OIDC_CLIENT_ID`                              | Public client identifier                                                                      | Nothing — it is not a secret                                                                                                                                 | —                                                                                     |
| `LOG_LEVEL`, `BETTER_AUTH_URL`, `OIDC_ISSUER` | Behaviour and addresses, not secrets                                                          | Nothing                                                                                                                                                      | —                                                                                     |

`BETTER_AUTH_SECRET` is the one to guard hardest: it is doing three jobs at once.
That is also why rotating it is disruptive, and why the procedure below is not
just "change the value and restart".

## Rotating BETTER_AUTH_SECRET

**What breaks, verified in the code and pinned by `src/server/security/secrets.test.ts`:**

1. **All sessions end.** Session tokens are signed with this secret, so every
   signed-in browser is logged out on the next request. Users sign in again.
2. **Every second factor stops working.** Better Auth encrypts the TOTP secret
   and the backup codes with this key (`symmetricEncrypt`/`symmetricDecrypt` on
   `secretConfig`). After rotation the stored ciphertext cannot be decrypted, so
   a user who is prompted for a code can never satisfy it — and the backup codes
   are unreadable too.
3. **Stored webhook signing secrets become unreadable.** CyberNorf seals each
   channel's HMAC key with a key derived from this secret (`scrypt`). A rotated
   secret makes `openSecret` throw, the delivery is recorded as failed, and
   alerting stops for those channels until the secret is re-entered.

### Procedure

1. **Announce the window.** Every user will be signed out, and every
   `OWNER`/`ADMIN` will be unable to complete the second-factor prompt until
   step 6.
2. **Inventory who has a second factor.** `SELECT "userId" FROM "twoFactor";`
   Keep the list; those users need re-enrolment.
3. **Note the notification channels.** Settings lists each channel. Whoever
   holds the signing keys must be ready to re-enter them.
4. **Stop the app.** A rolling restart is not safe here: two instances with
   different secrets would reject each other's sessions mid-flight.
5. **Generate and set the new secret.** With a mounted secrets directory, use
   `npm run secrets:rotate -- --name BETTER_AUTH_SECRET --dir /run/secrets/cybernorf --apply`,
   which writes the file atomically with mode `0600` and does not print the value. Otherwise
   `openssl rand -base64 48` into the deployment's secret store and the process
   environment. Never into the repository.
6. **Recover second factors.** For each user from step 2, delete the stale row so
   they can enrol again:

   ```sql
   DELETE FROM "twoFactor" WHERE "userId" = '<id>';
   ```

   This is a deliberate, logged administrative action; do it only after the
   account owner has been identified through a channel you trust, because the
   next person to sign in as that account sets a new factor.

7. **Re-enter webhook signing secrets.** For each channel, put the same signing
   key back in settings so it is re-sealed under the new secret, then send a
   test delivery.
8. **Start the app and verify:** `npm run config:check`, then `/api/ready`,
   then sign in, then a test alert delivery.
9. **Record it.** Note the rotation date, the reason, and the affected accounts
   in the change log.

Steps 6 and 7 are the reason this is a planned operation, not a routine one. If
a rotation is needed because the secret leaked, also review audit and
authentication activity for the exposure window — an attacker with the secret
could mint valid sessions for any account.

## Rotating CRON_SECRET

The sweep endpoint compares the bearer token in constant time and fails closed
when `CRON_SECRET` is unset. Rotation has no lasting effect:

1. Generate a new value:
   `npm run secrets:rotate -- --name CRON_SECRET --dir /run/secrets/cybernorf --apply`, or
   `openssl rand -base64 32` where secrets are plain environment variables.
2. Update the deployment environment and the scheduler's credential.
3. Restart the app and the scheduler together; a mismatched pair simply returns
   `401` and the next run recovers.
4. Confirm with one manual run: `curl -X POST -H "Authorization: Bearer $CRON_SECRET" https://<host>/api/cron/notifications`.

## Rotating the database password

1. Create the new password in PostgreSQL: `ALTER ROLE cybernorf WITH PASSWORD '<new>';`
2. Update `DATABASE_URL`, keeping `sslmode` unchanged. Changing the password does
   not change TLS settings; dropping `sslmode=require` on a remote database
   fails startup validation.
3. Restart. `npm run config:check` first, then `/api/ready` proves the app can
   reach the database with the new credential.
4. Confirm the old credential no longer connects before removing it from any
   secret store or backup.

## Rotating the identity-provider secret

1. Create the new client secret in the identity provider; most providers keep
   the old one valid for an overlap window.
2. Update `OIDC_CLIENT_SECRET` and restart. Sign-in through the provider should
   continue without interruptions.
3. Remove the old secret at the provider once a sign-in has succeeded.

Rotate during a period when at least one administrator can use password sign-in,
so a provider mistake cannot lock everyone out of the console.

## Rotating the package signing key

`EVIDENCE_SIGNING_KEY` signs portable evidence packages: HMAC-SHA256 over the
canonical manifest. It is symmetric, so whoever holds it can both verify a
package and produce one that verifies. Give it only to the recipients who must
check packages, and keep it with the archives when the key is retired.

1. Choose the next key id, for example `2026-12`, and generate the key:
   `npm run secrets:rotate -- --name EVIDENCE_SIGNING_KEY --dir /run/secrets/cybernorf --apply`.
2. Set `EVIDENCE_SIGNING_KEY_ID=2026-12` in the environment, restart, and confirm
   `server.started` reports `features.evidencePackages: true`. Packages issued from
   now on carry the new key id.
3. Keep the old key. A package is verifiable only with the key id and secret it
   was signed with, and `npm run evidence:verify-package` reads both from the
   environment, so verifying an old package means running it with the old pair.
4. Nothing is re-signed in place. A package already distributed stays valid under
   its own key id; re-issue it when the recipient needs it under the new key.

## Credentials issued inside the app

These never appear in the environment; rotate them in the UI or API, and revoke
rather than delete where the history matters:

| Credential             | Where                | Rotation path                                                                      |
| ---------------------- | -------------------- | ---------------------------------------------------------------------------------- |
| Agent enrolment token  | Agents page          | Issue a new token, enrol the host, revoke the old agent.                           |
| Machine credential     | Identities → machine | Rotate from the identity; one active credential per identity.                      |
| Personal API key       | Account → API keys   | Issue a new key, replace it in the automation, revoke the old.                     |
| Webhook signing secret | Notification channel | Replace in settings; stored sealed, not hashed, because the app must sign with it. |

## Mounted secret files

Environment variables are visible to anything that can read
`/proc/<pid>/environ`, are inherited by every child process, and appear in
`docker inspect` output and crash dumps. A file mount narrows that: the secret is
one file, owned by the service account, mode `0400`/`0600`, and never in the
process table.

`SECRETS_DIR` names one absolute directory. Each variable is one file whose name
is the variable name (`src/server/config/secrets-file.ts`):

| Behaviour   | Rule                                                                                                               |
| ----------- | ------------------------------------------------------------------------------------------------------------------ |
| Apply order | Files are loaded at startup **before** validation, so the validator sees the effective value                       |
| Precedence  | A file **wins over** the environment, so mounting a file and leaving the old variable in place is a safe migration |
| Allow-list  | Only the variables in `FILE_SECRET_VARIABLES` are read; any other file is reported as ignored, never applied       |
| Permissions | A file with any group or world permission bit is refused, and startup fails                                        |
| Whitespace  | One trailing newline and surrounding whitespace are stripped                                                       |
| Failure     | An unreadable or empty file is a startup error, never a silent fallback to the environment                         |

The startup log names the variables resolved from files (`secretsFromFiles`), so
"did the mount take effect" is answerable without exposing a value.

Rotating a mounted secret:

```bash
# validates and prints the plan; writes nothing
npm run secrets:rotate -- --name CRON_SECRET --dir /run/secrets/cybernorf

# writes <dir>/CRON_SECRET with mode 0600, atomically, value not printed
npm run secrets:rotate -- --name CRON_SECRET --dir /run/secrets/cybernorf --apply
```

The directory is an argument rather than a read of `SECRETS_DIR` on purpose: a
command that can replace a mounted secret should name its target explicitly
instead of inheriting whatever the calling shell happens to export.

`BETTER_AUTH_SECRET`, `CRON_SECRET`, `OIDC_CLIENT_SECRET` and
`EVIDENCE_SIGNING_KEY` can be generated this way; `DATABASE_URL` cannot, because
rotating it needs a matching change in PostgreSQL. The command refuses to
overwrite an existing file without `--force` and prints the blast radius of the
rotation it is about to perform.

## Configuration fingerprint

The process environment is not auditable: a restart replaces it silently. On
every boot the application records an HMAC-SHA256 digest of the effective
configuration in `system_settings` (`config.fingerprint`), keyed with
`BETTER_AUTH_SECRET`, and compares it with the digest from the previous boot.

- `configFingerprint.status` in the `server.started` log is `NEW`, `UNCHANGED`,
  `CHANGED` or `UNAVAILABLE` (database not reachable at boot).
- A change also logs `config.changed` with the first 12 hex characters of the
  digest. Two consecutive starts with the same digest log nothing.
- Only the digest is stored. No value, and no unkeyed hash of a value, is written
  to the database or the log — an unkeyed digest over environment variables would
  be a guessing oracle for anyone who can read the database.
- Variables that change on every start (`HOSTNAME`, `PWD`, `SHLVL`, `npm_*`, …)
  are excluded so a restart does not look like a change.

What it does not prove: the digest says **that** the configuration changed, not
which variable changed, in which direction, or who changed it. The change log
remains the authority for intent. An attacker with write access to the database
can also rewrite the stored digest, so this is an operational aid, not tamper
evidence.

## Handling the environment file

- `.env` and `.env.*` are ignored by git; only `.env.example` and
  `.env.production.example` are tracked. Keep it that way.
- Restrict permissions: `chmod 600 .env .env.test`. A world-readable file is a
  credential leak to any local process, including a compromised container build.
- CI scans history and the working tree with gitleaks, and `npm audit` runs at
  `low`. Passing CI is not proof a secret was never committed — history scans
  catch the shapes they know.
- Pass configuration through the orchestrator (Compose `env_file`, systemd
  `EnvironmentFile=`, Kubernetes `Secret`) where possible, so the value is not
  written to a checkout at all.

## Known gaps

Stated plainly, because the roadmap keeps this item open until they are closed:

- **No secrets-manager API integration.** There is no Vault, AWS Secrets Manager
  or GCP Secret Manager client and no sealed-secret support. A manager can still
  project into `SECRETS_DIR` with its own agent, which is the documented path, but
  the application does not talk to one itself.
- **Rotation is assisted, not scheduled.** `npm run secrets:rotate` generates one
  value safely and prints the drill; nothing watches for age, schedules a
  rotation, or verifies that the scheduler or identity provider was updated.
- **No rotation drill has been executed against a real deployment.** The
  consequences are pinned by unit tests and by reading the library, but the full
  procedure — including second-factor recovery and webhook re-sealing — has not
  been rehearsed end to end. The fingerprint record makes a rehearsal observable
  (`configFingerprint.status: CHANGED`), it does not perform it.
- **The audit trail records that the configuration changed, not what changed.**
  The digest in `system_settings` and the `config.changed` log line are
  deployment-level evidence, not a per-tenant audit event: there is no actor, no
  variable name, and no before/after value.
