# ADR 0007: Initial supported integrations

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

Integrations are where a small security product either becomes a hub or becomes a
maintenance burden. Each connector is an outbound network path, a credential to store, a
failure mode to page on, and a data-sharing decision. The shipped surface is a self-hosted
console with a database, a cron-driven alert sweep and no worker queue
([ARCHITECTURE.md](../ARCHITECTURE.md)), so the number of integrations that can be kept
honest is small.

Two integrations already exist and are load-bearing:

- **OpenID Connect** for single sign-on (`OIDC_*`), with PKCE, verified-email linking and
  an explicit all-or-none configuration rule ([SECRETS.md](../SECRETS.md)).
- **Outbound webhooks** for alerts, with a sealed signing secret, an HMAC signature, SSRF
  and DNS-rebinding protections, bounded retries and a delivery record
  (`notification_channels`, `notification_events`).

## Decision

The first release supports exactly those two integration directions:

1. **Identity in:** one OpenID Connect provider. No SAML, no SCIM, no directory sync, no
   automatic de-provisioning. Those are Phase 5 items and each needs a different failure
   model (attribute mapping and group sync are not the same problem as authentication).
2. **Events out:** tenant-configured webhooks, signed. The payload is the alert, not the
   whole record; a receiver that wants the record fetches it through the API with a
   scoped credential.

Everything else is explicitly out of the first release:

| Candidate | Why not now | What would reopen it |
| --- | --- | --- |
| SIEM (syslog, CEF, Splunk HEC) | Duplicates the audit trail into a system with different retention and access rules; needs a stable event schema and back-pressure before it is safe to ship. | A design partner who must ingest the audit chain into an existing SIEM, plus a versioned event schema. |
| SOAR / automation callbacks | Requires inbound authenticated actions with replay protection and per-action authorization; that is Phase 4 machinery. | The Phase 4 scope model and job isolation landing first. |
| Ticketing (Jira, ServiceNow) | Bidirectional sync creates a second source of truth for findings; one-way creation is a smaller feature that can wait for demand. | Repeated requests to create tickets from findings, with an idempotency design. |
| Gateway / firewall / EDR connectors | Pulling device data turns the product into a collector with its own credential vault and rate-limit budget. | A concrete feed and a proven need that the agent inventory cannot cover. |
| Chat (Slack, Teams) | Webhooks already reach chat through an incoming-webhook URL; a native app adds OAuth and a second permission model for little gain. | Demand for interactive actions from chat, which needs the same inbound-auth work as SOAR. |

## Consequences

- The integration surface stays auditable: one inbound protocol, one outbound protocol,
  both already covered by tests and by [THREAT_MODEL.md](../THREAT_MODEL.md).
- Customers who need SIEM or ticketing use the export route or the API instead of a
  connector. That is a supported answer, not a workaround.
- Adding an integration later requires an ADR that names the credential storage, the
  failure and retry behaviour, the data that leaves the tenant, and the test that proves
  the boundary. "There is an API" is not an integration design.
- The Phase 0 roadmap item closes on this decision; the table is the record of what was
  considered and why it was deferred.
