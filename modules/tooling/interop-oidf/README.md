# interop-oidf

## Responsibilities
- The ledger of the provider's intended deviations and strict choices (L1), `docs/compliance/deviations.json`, which a conformance run's expected failures name by key, and the public page written from it (internal module `deviations`).

## Not here
- A certification: L1 takes none on a weakened configuration.
- The provider's modules and their own tests.

## Offers
- `pnpm --filter @mod/interop-oidf run deviations`: writes `docs/compliance/deviations.md` from `docs/compliance/deviations.json`.

## Invariants
- No package depends on this one: it is verification, unpublished.

## Depends on
- No workspace package.
