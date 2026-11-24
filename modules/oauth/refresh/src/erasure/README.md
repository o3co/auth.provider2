# erasure

Internal module of `refresh`: erasing a subject's records, and reading whose a record is.

## Responsibilities
- The eraser `refresh`, contributed to `erasure-extensions`' `erasers`, as the records' space's `erasedBy` names it.

## Not here
- What the store keeps and how it fences (the Store). When erasure runs (`account-erasure`).

## Offers
- `familyEraser` (the store) → the eraser: a subject's records erased through the store's `erase`, a window doing the same for each subject, `migrate` with `familySubjectOf`; `erasable` only where the store offers both ports.
- `familySubjectOf`: the migration's reading, each record's own subject. `portsRefused` (the store) → why its ports cannot be used, or none.

## Invariants
- Every record keeps its subject: a family, the key bound to it, a code's link or mark. A record of no kind refresh names, or of another shape, is unreadable, never an orphan.
- Each port is called on the store, so an implementation keeps its own `this`. The eraser's build takes only the store.

## Depends on
- `erasure-extensions` (`Eraser`, `SubjectReading`); the package's store interface and records.
