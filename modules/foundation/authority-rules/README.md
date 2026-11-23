# authority-rules

## Responsibilities
- Holds the transparency core's judgment rules as one library the Core's local check and the monitor run alike, so both give one answer: Allowed (the chain rules), the one fold and stateOf over a flow, the verdict by the judgment table and the outcome.
- Owns the schemas transparency-wire leaves to it: a flow's state, a record's changes, and a Core writer's preimage content by kind.

## Not here
- The words, the records' and the receipts' forms, the verdict and outcome words: `transparency-wire`. T's items and statements: `sdk-core-wire`.
- Signing, decrypting, hashing and verifying: the caller's, passed in as functions. Reading the log, the clock, keeping the judged prefix: the caller's.
- The intent frame, leases, the owner rule and the end-of-intent table, which the Core alone runs: the Core's `transparency`.
- Whether a receiver takes a record (`Acceptable`, read off a status, not a judgment): the receivers' parts.

## Offers
- `allowed` (an `Ask`: the record's named fields, its opened preimage, its flow's state and judged prefix, the `Checks`, the `Context`) → `Allowance`, the first rule broken (internal module `chain`).
- `timely` (an `Ask`, the acceptance time): TimeOK. `effectOf` (an `Ask`): Eff(r), the changes a Core record makes, the same in the Core's intent and the monitor's fold.
- `judge` (a `Reading`: the placed record, what opening its preimage gave or another writer's verified body, the key sets, the versions' windows, the prefix) → `Ruling`: the flow entry with its verdict and outcome, the row J0–J13, whether counted; or a wait (internal module `judgment`). `outcomeOf` (a `Reading`, a verdict).
- `fold` (state, `Envelope`, `Changes`, `Finding`) → the state; `foldFlow` (flow, entries) → transparency-wire's stateOf; `emptyState` (internal module `fold`).
- `ruleSchemas`: `flowState`, `changes`, and `contents`, each Core kind's preimage content (internal module `evidence`).
- Types: `Ask`, `Named`, `Allowance`, `Checks`, `Context`, `RuleTimes`, `Reading`, `Opening`, `Window`, `Ruling`, `Row`, `FlowRecord`, `FlowEntry`, `FlowState`, `Changes`, `Envelope`, `Finding`, `RecordKind`.

## Invariants
- Pure: no I/O, clock, randomness, crypto or state. A record's fields, its flow's judged prefix (the entries from position 1 and the state they fold to) and the caller's functions in; a value out. A caller's error of shape (entries out of order, a Core record without its opening) is a TypeError.
- The one fold (PR-ONE-FOLD) changes the state only for a record verified or unsupported that took, and picks one effect by kind; nothing else changes a state. No change carries a reset, which no rule allows.
- The verdict is the first row of the table it meets, in the table's order; the chain (J7) is checked before the time, and a forged row before an inherited hold (J9).
- A Core record is held to the ring of its writer's Core generation, the context's: a statement of another generation's ring is forged. A first key's key generation is the signed creation's.
- Another writer's record is judged with the body its signature verified (`signedRecord`); a role naming a kind it does not write is forged.
- What the rules hold no rule for is refused, never passed: a key change other than the first-key path, and a person's op off a subject flow.

## Depends on
- `transparency-wire`, `sdk-core-wire` (the protocols); `zod`.

## Vocabulary
- state (S, M): a flow's live keys, approvals and families by the record that made each, its key generation and use-once marks.
- changes (e): what a record's writer left for the fold. entry: a judged flow position (envelope, changes, judgment, parent).
- root: the first-trust key's registration a chain rests on; a chain: the registrations from it down.
- verdict, outcome, row: the judgment table's (kernel-spec §6.1, §6.2).
