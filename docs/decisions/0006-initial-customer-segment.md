# ADR 0006: Initial customer segment and problem

- **Status:** Proposed — a working assumption, not validated by a customer
- **Date:** 2026-11-11

## Context

Phase 0 asks for a segment and a problem before more surface is built. The product
already behaves as if both were chosen: it is self-hosted, it keeps findings, incidents
and compliance evidence, and it deliberately has no scanner, no exploitation and no
agent-driven offensive capability ([README.md](../../README.md#intended-users-and-deployment),
[ADR 0004](0004-production-deployment.md)).

Writing an ADR cannot validate a market. What it can do is state the assumption in a form
that a customer conversation can falsify, so the roadmap item stays open until that
conversation happens rather than being closed by this document.

## Decision

**Segment:** small defensive security teams — one to ten practitioners — who own
vulnerability management, endpoint hygiene and audit preparation for a single
organization, and who do not run a SOC platform.

**Problem:** they cannot answer three questions with the tools they can afford to operate:

1. _What is exposed, what is wrong with it, and what are we doing about it?_ Findings live
   in spreadsheets and inboxes; nothing connects a check result to an owner, a deadline and
   a fix.
2. _Can we prove what we did?_ Auditors ask for control evidence and a history of who
   changed what. Screenshots in a shared drive are not a chain of custody.
3. _Who and what can reach our systems?_ Service accounts, API clients and monitoring
   agents are outside any inventory, and nobody reviews them.

**Product consequence:** the shipped workflow is the case record, not detection. The
product assumes checks and advisories come from something the customer already runs
(the bundled monitor, an imported feed) and concentrates on the record, the deadline, the
evidence and the audit trail around them.

## What would confirm or falsify this

The assumption is confirmed when at least three of five design-partner teams, after using
a seeded tenant for two weeks, keep using it for a real audit or incident and say the
record — not detection — is what they lacked. It is falsified by any of:

- prospects consistently asking for scanning or offensive testing first, which is Phase 4
  territory and explicitly out of scope until the foundation is reviewed;
- teams with more than ten practitioners finding the product too shallow to replace the
  SOC tooling they already have;
- self-hosting being the blocker in every conversation, which would reopen ADR 0004 and the
  hosted model rather than this segment.

Until that evidence exists, the roadmap item stays unchecked and
[README.md](../../README.md#intended-users-and-deployment) keeps calling the segment a
working assumption.

## Consequences

- Features are judged by "does this help a small team keep a defensible record?", not by
  detection coverage.
- Enterprise-only capabilities (SAML, SCIM, scheduling, multi-region) stay in Phase 5 and
  are not allowed to displace the case-record work.
- The self-hosted constraint is part of the segment hypothesis, not an implementation
  detail: if the segment turns out to require a managed service, both this ADR and ADR 0004
  are wrong together.
