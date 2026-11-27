# deviations

Internal module of `interop-oidf`: the provider's intended deviations and strict choices (L1), the ledger `docs/compliance/deviations.json` and the public page written from it.

## Responsibilities
- Reads the ledger, one row each: its key, its kind (`deviation`, `strict`), the standard and its text, what nextgen does, why, and the decision that chose it.
- Writes the public compliance page `docs/compliance/deviations.md` from it.

## Not here
- How a conformance run is judged by the rows its expected failures name.
- Choosing a row's words: review's, the ledger's being the one place they are written.

## Offers
- `ledger` (the repository's) and `ledgerOf` (a text) → `Deviation` rows, refused where any may not be taken; `ledgerProblems` (a value) → why not; `pageOf` (rows) → the page; `ledgerPath`, `pagePath`.
- `pnpm --filter @mod/interop-oidf run deviations`: writes the page from the ledger.

## Invariants
- A row has every field, none empty and none other; its key is lowercase words joined by `-` and named once; its kind is `deviation` or `strict`.
- The page is the ledger written out, rows in the ledger's order, a cell on one line with `|` escaped; the repository's page is held to it, so the ledger is the one place a row is written.

## Depends on
- No workspace package.
