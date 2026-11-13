# ADR 0009: Recorded decisions, derived device trust and audited enforcement

- **Status:** Accepted
- **Date:** 2026-11-13

## Context

The platform could observe (assets, findings, agents, identities) and, since Phase 4, act inside an approved engagement. Zero Trust asks for a different shape of behaviour: not "what is wrong with this asset" but "may this request proceed, and what stops it when the answer is no".

That shape has three properties the earlier phases did not need:

- **A verdict is only defensible with its inputs.** "Denied" printed next to a request is an assertion. A decision that stores the facts it was evaluated against — device trust state at that moment, the zone resolved from a stored segment, connector health, second-factor state, risk score — is evidence. If the caller supplies those facts, the record proves nothing.
- **Claims from an endpoint are hostile until proven.** A device reporting its own disk-encryption status, a gateway reporting its own liveness, a build service reporting its own artifact digest: each is a claim. Accepting an unsigned claim makes the control decorative, because the party that benefits from a permissive answer is the party making it.
- **Enforcement is destructive in a way observation is not.** Quarantining the wrong device, revoking the wrong session, or pushing a rollback is an outage caused by the security tool. Duplicate commands, self-approved commands, and commands that stay armed forever are failure modes that must be designed out rather than handled by convention.

This ADR records the slice that ships, and the boundaries that remain.

## Decision

### One decision point that records facts, not just verdicts

- `PolicyRule` is ordered by ascending `priority`; the first rule whose every declared condition passes decides. When no rule matches, the answer is `DENY` — there is no default allow and no implicit "no policy means yes".
- Conditions are a closed vocabulary (`roleIn`, `attributeEquals`/`attributeIn`, `deviceTrustAtLeast`, `deviceManaged`, `postureFresh`, `postureCheckPassed`/`Failed`, `mfaSatisfied`, `zoneIn`, `connectorStatusIn`, `sensitivityAtLeast`, `riskAtLeast`, `resourceTypeIn`, `actionIn`, `approvalStateIn`, `outsideBusinessHours`). An unknown key makes the rule invalid rather than ignored, so a typo cannot silently widen a rule.
- Facts are resolved server-side from stored records in `policy-facts.ts` — device row and its newest posture, segment lookup for the source address, connector health, membership role, approval state. A caller can describe a request; it cannot assert its device is trusted.
- `PolicyDecision` stores the request context, the resolved facts, the risk score with its contributing factors, the matched rule and a structured explanation. Verdicts are `ALLOW`, `DENY`, `STEP_UP` and `QUARANTINE`, so a "no, unless the user proves more" answer is expressible without collapsing into a deny.
- Risk is a weighted sum over named factors (`src/server/domain/zero-trust.ts`), not a learned model. Every factor that contributed is stored, because "risk 62" without the reasons is not reviewable.

### Device trust is derived, never assigned

- A device registers with a public key. `POST .../devices/:id/posture` accepts a signature over the canonical serialization of `{ deviceId, collectedAt, checks }`; a report whose signature does not verify against that device's key is stored with `signatureVerified: false` and **cannot** raise trust.
- Trust is a pure function of stored state: verified and fresh posture, the pass ratio of the checks, whether the device is managed, and whether attestation was verified. Failed checks cap the device at `UNTRUSTED`, unknown checks and unmanaged devices at `PARTIAL`, and each state has a score ceiling so a device with three checks cannot out-score a fully verified one.
- Stale posture is a first-class state: a report past `expiresAt` leaves the device `UNKNOWN` with reason `posture_stale`. Nothing keeps a verified report alive indefinitely.
- Trust derivation reads the device status: `PENDING` returns `UNKNOWN` with reason `awaiting_activation`, `SUSPENDED` and `RETIRED` return `UNTRUSTED`. A posture report can be stored before activation, but registration alone cannot create an admitted endpoint.

### Admission is a decision with a defined failure mode, not a routing wish

- A connector is `ONLINE`, `DEGRADED` or `OFFLINE` from its own heartbeat, and carries a `failMode`.
- `POST .../network/admission` evaluates policy, then applies the connector state: online → the policy verdict stands; offline with `CLOSED` → the device is not admitted and the reason is `connector_unreachable_fail_closed`; offline with `OPEN` → the policy verdict stands but the unreachable connector is recorded with it.
- The zone is resolved from the stored `NetworkSegment` containing the source address, not from a zone the caller names. An address in no segment has no zone, which is a fact the policy can deny on.
- The admission record stores the decision id, the assigned zone and the reason, so the connector's action and the platform's reasoning stay linked.

### Enforcement is four-eyes, idempotent and expiring

- States are `REQUESTED → APPROVED → DISPATCHED → ACKNOWLEDGED → VERIFIED`, with `REJECTED`, `FAILED` and `EXPIRED` terminal. A transition that is not in the table is refused, so a "verified" command cannot skip acknowledgement.
- A request cannot be approved by the person who made it. `ENDPOINT_ISOLATE`, `NETWORK_QUARANTINE`, `FIREWALL_BLOCK` and `CERT_REVOKE` additionally require a distinct second approver, because each removes or interrupts a device; `SESSION_REVOKE` deliberately does not, so an operator can end a session during an incident without waiting for a peer. The distinction is a closed table in the domain module, recorded on the action rather than left to a caller's judgement.
- `(organizationId, idempotencyKey)` is unique, so a retry after a timeout returns the original action instead of sending a second command.
- Every request carries `expiresAt`. An approval after that moment is refused, and the sweep expires both unapproved requests and dispatched commands that were never acknowledged — a command that nobody confirmed does not stay armed silently.
- Connectors authenticate with their own bearer token on `/api/v1/connectors/*`, are rate limited per address and per token, and each handler checks that the action being acknowledged, failed or verified is bound to that connector. A connector cannot acknowledge another connector's command.

### Releases are verified artifacts, not uploaded builds

- Publishing verifies the manifest signature against `ZERO_TRUST_PUBLISHER_KEYS`, held in the environment rather than the database so a database compromise cannot mint a release the platform would accept. Publishing with an unknown key id fails instead of storing an unverifiable artifact.
- The release stores artifact URL, SHA-256, manifest, signature, publisher key id, compatibility window and an optional `minVersion` anti-rollback floor. A device below the floor is not offered the build.
- Rollout is one-way through `DRAFT → CANARY → ROLLING → RELEASED`; rollback moves a release to `ROLLED_BACK` and stops new offers. Offering twice is idempotent on `(deviceId, releaseId)`, and install results are reported per device and stored.

### Everything above lands in the audit chain in the same transaction

- Decisions, device lifecycle, connector creation and rotation, admission, enforcement transitions, release publishing, rollout and rollback each append an audit event with the mutation.
- Machine-actor events (a connector heartbeat, a system expiry sweep) are written with the `SYSTEM` actor. The alternative — writing a connector id into the actor column — violated the actor foreign key and turned every heartbeat into a 500, which the integration tests now cover.

## Consequences

- **No RADIUS or 802.1X server ships.** The platform computes and records an admission decision and hands the outcome to an operator-run connector. It does not terminate EAP-TLS, does not hold a certificate authority, and does not programme a switch VLAN itself. The README and roadmap say so rather than implying a NAC appliance.
- **The decision point is an operator API, not a device-facing PDP.** `POST .../policies/evaluate` requires `policy.manage`, and `POST .../network/admission` requires `network.manage`. A gateway therefore cannot ask the platform "may this device join?" with its own connector token in this revision; the admission call is made by an operator or an automation holding a tenant credential. Making the PDP connector-reachable is the next step and is recorded as remaining.
- **Attestation is recorded, not verified.** `attestationKind` and `attestationVerified` are stored on the device and the trust function consumes them, but no TPM or Secure Enclave quote is validated. `TRUSTED` is reachable only when an operator has asserted attestation, which is a claim the platform cannot check.
- **Detection is rule-based over ingested flows.** Five rules (`port_scan`, `quarantine_egress`, `ot_external_inbound`, `external_egress`, `bulk_transfer`) run over bounded flow batches. There is no packet capture, no deep inspection, no TLS metadata, and no topology graph; a detection is only as good as the connector that fed it, which is why it carries `freshUntil` and the observations behind it.
- **Policy is a first-match rule list, not an expression language.** No nested boolean groups, no tag dictionaries, no per-resource exceptions beyond what the condition keys express. This is deliberate: a rule that cannot be explained in a sentence cannot be reviewed by a small team.
- **Update delivery stops at offer and report.** The platform does not serve artifacts, does not compute deltas, does not sign the artifact itself (only the manifest), and does not revert an installed build — rollback stops offers. Publisher key rotation is an environment change and a restart; there is no overlap window and no per-key revocation list.
- **Risk scoring is heuristic.** Weights are visible and tested, but they are not calibrated against real incident data, and a `riskAtLeast` condition is only as meaningful as the factors behind it.
- **The surface area grew by five console sections, eleven tables and five capability groups.** Each addition had to touch the capability matrix, the audit action list, the validation schemas and the navigation together; that coupling is the cost of keeping authorization and audit complete, and it is the main reason the modules are separate services rather than one.
