# Findings: risk scoring and remediation SLAs

Every finding carries two derived columns, `riskScore` and `dueAt`, computed by
`src/server/domain/risk.ts`. They are recomputed on every write path (manual
create/update, import, agent check findings, advisory matches, and asset
criticality changes) so ordering and dashboards never read stale values.

## Risk score

`riskScore` is an integer in `0–100`, used for prioritisation and sorting, not
for compliance judgement. It is deliberately explainable:

| Severity | Base |
| -------- | ---- |
| CRITICAL | 90   |
| HIGH     | 70   |
| MEDIUM   | 45   |
| LOW      | 20   |
| INFO     | 5    |

A supplied CVSS score blends toward its own 0–100 scale with a weight of 40%:

```
blended = base * 0.6 + clamp(cvss, 0, 10) * 10 * 0.4
```

Asset criticality then applies a bounded multiplier: `CRITICAL 1.25`,
`HIGH 1.15`, `MEDIUM 1.0`, `LOW 0.85`, and no multiplier for findings without an
asset. The result is rounded and clamped to `100`. Check-based agent findings
carry no asset relation, so they are scored from severity alone until an analyst
links them to an asset.

## Remediation windows

`dueAt` is measured from `firstSeenAt`, not from the row's creation time, so a
re-import or a status change never moves the deadline forward. A finding that
is imported for the first time starts its window at import; later imports of the
same fingerprint only refresh `lastSeenAt`.

| Severity | Days |
| -------- | ---- |
| CRITICAL | 7    |
| HIGH     | 30   |
| MEDIUM   | 90   |
| LOW      | 180  |
| INFO     | 365  |

Changing a finding's severity moves its deadline relative to the same original
observation; editing a title or description does not.

`remediationState()` derives one of:

- `OVERDUE` — past `dueAt` and still open.
- `DUE_SOON` — due within seven days.
- `ON_TRACK` — later than seven days.
- `CLOSED` — `RESOLVED`, `ACCEPTED_RISK` or `FALSE_POSITIVE`; never overdue.
- `UNSCHEDULED` — no deadline recorded (legacy rows).

## Dashboard metrics

`getDashboardSummary()` returns a `remediation` block:

- `overdue` and `dueSoon` — counted in SQL over open findings, so they stay exact
  regardless of table size.
- `open` — open findings across all severities.
- `slaCompliance` — percentage of findings resolved within their deadline over
  the last 90 days, or `null` when nothing was resolved. Computed from at most
  5,000 most-recent resolutions.
- `meanTimeToResolveDays` — mean `resolvedAt - createdAt` over the same window.
- `resolutionSampleSize` and `windowDays` — the basis for the two figures.

## API and UI

`GET /api/v1/organizations/{orgSlug}/findings` accepts `overdue=true` (open,
past deadline) and sorts on `riskScore` or `dueAt`. The findings page exposes the
same filter as an "Overdue only" checkbox and shows the score and deadline with
its state; the dashboard links straight to the filtered list.
