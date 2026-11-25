# state

Internal module of `refresh`: its part of a subject's flow, the state's families as the log's fold leaves them.

## Responsibilities
- Owns the families of a subject flow's state for `transparency` (`familiesOwner`): reads them from its part's record, and writes the record from the state after a fold.

## Not here
- Which families a record makes, rotates, abandons or drops: `authority-rules`' fold. A family's own records (its secret, its rotation, its rooted list): the package's store interface. Binding the part to a space: the store wiring.

## Offers
- `familiesPart`, the part's name, which the package's contract offers to its wiring; `familiesOwner`, the `StateOwner` the package contributes to `transparency`'s `stateOwners`.

## Invariants
- It holds the state's families alone; any other field is another owner's.
- A record holding none reads as no families; the record is written only where the families changed.

## Depends on
- `transparency` (`StateOwner`), `sdk-core-wire` (the canonical text).
