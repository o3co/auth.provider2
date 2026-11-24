# erasure

Internal module of `claims-selection`: erasing a subject's selections, and reading whose a record is.

## Responsibilities
- The eraser `claims-selection`, contributed to `erasure-extensions`' `erasers`, as the selections' space's `erasedBy` names it.

## Not here
- What the store keeps and how it fences (the Store). When erasure runs (`account-erasure`).

## Offers
- `selectionEraser` (the store) → the eraser: a subject's selections erased through the store's `erase`, a window doing the same for each subject, and `migrate` with `selectionSubjectOf`; `erasable` only where the store offers both ports, empty reports where not.
- `selectionSubjectOf`: the migration's reading, each record's own subject.
- `portsRefused` (the store) → why its ports cannot be used, or none: `erase` and `migrate` together or neither, a part refused at build; `portsOf` → both, or none.

## Invariants
- A record of no kind claims-selection names, or of another shape, is unreadable, never an orphan.
- Each port is called on the store, so an implementation keeps its own `this`.
- The eraser's build takes only the store, collecting no probes: the erasure gate collects erasers.

## Depends on
- `erasure-extensions` (`Eraser`, `SubjectReading`); the package's store interface and record format.
