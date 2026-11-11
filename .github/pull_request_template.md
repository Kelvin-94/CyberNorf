## What changed

<!-- One paragraph. Link the issue when one exists. -->

## Why

<!-- The problem this solves and the security or operational impact. -->

## Verification

<!-- Commands run and their actual result. Do not claim a check you did not run. -->

- [ ] `npm run lint`
- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `npm run build`

## Security review

- [ ] No credentials, tokens, private keys, customer data, or production logs are included.
- [ ] No new install-time script (`preinstall`, `install`, `postinstall`, `prepare`) or remote script execution was added.
- [ ] New or changed dependencies are justified below and come from the public npm registry.
- [ ] Workflow changes keep actions pinned to full commit SHAs and permissions least-privilege.
- [ ] New input paths validate at the trust boundary; new authorization paths deny by default.
- [ ] Audit coverage and tenant scoping were considered for every new mutation or read path.

## Dependencies and migrations

<!-- List new packages with their purpose, or write "none". -->

## Limitations and follow-up work

<!-- Known gaps, deliberate scope cuts, or residual risk. -->
