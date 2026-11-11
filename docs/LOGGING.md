# Application logging

The platform writes structured logs for the failures an operator has to see:
unhandled request errors and startup problems. Everything else already has a
durable, queryable home — the audit trail in PostgreSQL records who changed
what, and the reverse proxy records one line per request.

This document covers the record format, the redaction guarantee, the level
control, and how to ship the output to a collector.

- [Record format](#record-format)
- [Levels](#levels)
- [What is logged today](#what-is-logged-today)
- [What is never logged](#what-is-never-logged)
- [Redaction](#redaction)
- [Shipping and rotation](#shipping-and-rotation)
- [Writing a log line](#writing-a-log-line)
- [Tests](#tests)

## Record format

One JSON object per line on stdout, terminated by a newline and written in a
single `write()` call so a line-oriented collector never sees a split record.

```json
{
  "time": "2026-11-11T09:14:02.117Z",
  "level": "error",
  "msg": "request.unhandled_error",
  "service": "cybernorf",
  "env": "production",
  "requestId": "0f1c1d2e-…",
  "error": {
    "name": "PrismaClientKnownRequestError",
    "message": "Timed out fetching a new connection from the pool.",
    "code": "P2024"
  }
}
```

| Field       | Always present | Notes                                                                                            |
| ----------- | -------------- | ------------------------------------------------------------------------------------------------ |
| `time`      | yes            | ISO-8601 UTC, generated at write time.                                                           |
| `level`     | yes            | `debug`, `info`, `warn`, or `error`.                                                             |
| `msg`       | yes            | Stable dot-separated event name (`request.unhandled_error`), not prose.                          |
| `service`   | yes            | `cybernorf`; lets a shared collector separate this app from the proxy.                           |
| `env`       | yes            | `NODE_ENV`, defaulting to `development`.                                                         |
| caller keys | no             | Any field the call site passes, for example `requestId`, `agentId`.                              |
| `error`     | on failures    | `{ name, message }`, plus `stack` at `error` level and primitive extras such as Prisma's `code`. |

`msg` is the field to group and alert on; `requestId` is the field to join an
application log line to the `x-request-id` returned to the client and printed
by the proxy.

## Levels

`LOG_LEVEL` sets the minimum level the process emits. Accepted values are
`debug`, `info`, `warn` and `error`; anything else — including an unset value or
different casing — falls back to `info`, so a typo cannot silence the process.

| `LOG_LEVEL`      | Emitted                 | Typical use                                     |
| ---------------- | ----------------------- | ----------------------------------------------- |
| `debug`          | everything              | Reproducing a failure in a staging environment. |
| `info` (default) | `info`, `warn`, `error` | Normal production.                              |
| `warn`           | `warn`, `error`         | Noisy periods where only faults matter.         |
| `error`          | `error`                 | Minimum viable production signal.               |

Set it in the deployment environment, not in `.env.example`. The level is read
once per logger instance; restart the app to apply a change.

## What is logged today

| Event                     | Level | Where it comes from            | Fields                                                                                                |
| ------------------------- | ----- | ------------------------------ | ----------------------------------------------------------------------------------------------------- |
| `request.unhandled_error` | error | `src/server/errors.ts`         | `requestId`, `error`                                                                                  |
| `server.started`          | info  | `src/instrumentation.ts`       | `nodeVersion`, `logLevel`, `features.oidc`, `features.signedAgentRunsRequired`, `features.alertSweep` |
| `logging.failed`          | error | `src/server/logging/logger.ts` | `error` (the serialisation failure)                                                                   |

`server.started` is written once, after the startup security checks pass. It
records the Node version, the effective log level and which optional features
are configured — booleans only, never the issuer URL, the secret or the sweep
credential itself. A deployment that fails those checks exits before the line
is written, so the absence of `server.started` is itself a signal.

Two things are deliberately **not** duplicated into this stream:

- **Request access logs.** Caddy writes one JSON line per request, including
  status, duration and `x-request-id`, and never records `Authorization` or
  `Cookie` headers. Logging every request twice would double volume without
  adding information.
- **Audit events.** Sign-ins, permission changes, finding updates and agent
  actions are stored in `audit_events` with hash-chained integrity, exposed at
  `/audit` and included in exports. The audit trail is the authoritative record
  of who did what; log lines are for operational diagnosis.

## What is never logged

- Passwords, password hashes, TOTP secrets and recovery codes.
- Session cookies, bearer tokens, agent tokens and API keys.
- Request or response bodies, headers, and query strings in full. Log the
  `requestId` and the route instead, then fetch the audit or proxy record.
- Database connection strings and OIDC client secrets.

This is enforced twice: call sites do not pass these values, and every record
passes through the shared redactor before it is written.

## Redaction

`src/server/logging/logger.ts` assembles the record, then passes it through
`redactValue()` from `src/server/security/redaction.ts` — the same primitives
the audit trail uses, so the two cannot drift.

Two independent passes run over the whole record:

1. **Key-based.** Any key whose normalised name is a known secret
   (`password`, `secret`, `token`, `authorization`, `cookie`, `set-cookie`,
   `apikey`, `clientsecret`, `webhooksecret`, `totpsecret`, and similar) is
   replaced with `[redacted]` at any depth, including inside arrays and nested
   objects.
2. **Value-based.** Credential-shaped strings are replaced wherever they appear,
   even under an innocent key: GitHub and Slack tokens, `Authorization: Bearer …`
   headers, `?token=…` / `?signature=…` URL parameters, `password=hunter2`
   pairs, and JWTs.

Redaction is bounded and circular-safe: depth and array length are capped, a
circular reference is replaced by a marker rather than recursing forever, and
the error `stack` is truncated. Logging never throws — if serialisation or the
sink fails, the logger emits one `logging.failed` line, and if even that fails
it drops the record instead of failing the request it was describing.

Redaction is a last line of defence, not a licence to pass secrets in. A value
the patterns do not recognise — a random opaque identifier, a customer name, a
hostname — will be logged verbatim. Treat log output as potentially sensitive
and restrict access accordingly.

## Shipping and rotation

The app writes to stdout and does not manage files, rotate them, or open a
network connection to a collector. That is the platform's job:

- **Docker Compose.** `docker compose -f compose.prod.yaml logs -f app` reads
  the stream; configure the `json-file` driver's `max-size`/`max-file` options
  or use `local`/`journald` to bound disk use.
- **systemd.** `StandardOutput=journal` puts the lines in the journal; use
  `journalctl -u cybernorf -o cat` to read them without systemd's own prefix
  breaking the JSON.
- **Kubernetes.** The container runtime's log driver captures stdout; point a
  node agent (Fluent Bit, Vector, Promtail) at `/var/log/containers` and parse
  the JSON body.

Because every line is complete JSON starting with `time`, `level` and `msg`,
no multiline configuration is required. If you add a second replica, do not
merge the two stdout streams by position; group by `requestId`.

## Writing a log line

Import the shared logger, never `console`:

```ts
import { logger } from '@/server/logging/logger';

const requestLog = logger.child({ requestId, organizationId });
requestLog.warn('agent.report_late', { agentId, minutesLate: 12 });
```

Rules for call sites:

1. `msg` is a stable event name, not a sentence with interpolated values; put
   the values in fields so they stay queryable.
2. Pass `Error` objects as `error`, not stringified messages — the logger keeps
   `name`, `message`, primitive extras, and the stack at `error` level.
3. Do not log bodies, headers, credentials, or personal data.
4. This module writes to `process.stdout` and is Node-only. It must not be
   imported from `src/proxy.ts` or any code that runs on the edge runtime.

## Tests

- `src/server/logging/logger.test.ts` — record shape, level threshold, key and
  value redaction, error serialisation, child bindings, circular input,
  failing sink, `LOG_LEVEL` parsing.
- `src/server/errors.test.ts` — proves the wire-up end to end: an unhandled
  error produces exactly one redacted line, the response stays a generic 500,
  and the request id is returned for correlation.

Run them with `npx tsx --test src/server/logging/logger.test.ts src/server/errors.test.ts`.
