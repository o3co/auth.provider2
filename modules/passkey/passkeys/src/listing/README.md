# listing

Internal module of `passkeys`: the list of a subject's keys, with the label its person gave each and when each was reserved, and renaming a key.

## Responsibilities
- Answers `listOf` from the applied state and the credential records, and `rename` by changing a record's details.

## Not here
- Writing a reservation's time: the internal module `registering`, as it binds a credential. Who may rename, on whose approval, and the list's completion: the key management package and `approvals`.

## Offers
- `listingOver` (the frames, the credential store, the clock) → the package's `KeyList`:
  - `listOf` (subject) → each active key's credential, label and reservation time, where its record holds them, in the applied state's order.
  - `rename` (subject, credential, label, `by` statement hash, number and its statement's end; another shape is thrown) → `renamed`, `unknown` (not an active key of the subject's), `stale` or `label`.
- `isKeyLabel`: the label's rule, the list's in `sdk-core-wire`.

## Invariants
- A label is kept only where it follows the list's rule, and given only while it still does: a list never fails on a label kept.
- `listOf` answers every active key; above `max-credentials` only for a subject that held them before its cap was lowered (none before 0.1.0).
- `rename` writes only a record that binds the subject and keeps its details, and decides in that write. The record keeps the last number of each statement that renamed it until that statement's end, when no step of it runs (dropped at the next write past it, one clock reading deciding a write): a paused step that wakes after later renames, of its statement or another, is stale.
- A write past its statement's end, an earlier number of a statement kept, or its own number with another label, is `stale` and changes nothing; the same number with the same label changes nothing and is `renamed`, so a step run again is answered alike.
- The label and the time go with the details: dropped once the key is gone (the package's `settle`), released with the binding.

## Depends on
- `transparency` (the frames' types); the package's contract, records and the internal module `kept`.
