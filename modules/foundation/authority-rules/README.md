# authority-rules

## Responsibilities
- Holds the transparency core's judgment rules as one library the Core's local check and the monitor run alike, so both give one answer: Allowed (the chain rules), the one fold, the verdict by the judgment table and the outcome.
- Owns the schemas transparency-wire leaves to it: a flow's state, a record's changes, and a Core writer's preimage content by kind.

## Not here
- The words, the records' and the receipts' forms, the verdict and outcome words: `transparency-wire`. T's items and statements: `sdk-core-wire`. A continuation's stages and bytes: `continuation-wire`.
- Signing, decrypting, hashing and verifying: the caller's, passed in as functions. Reading the log, the clock, keeping the judged prefix: the caller's.
- The intent frame, leases, the owner rule and the end-of-intent table, which the Core alone runs: the Core's `transparency`.
- Whether a receiver takes a record (`Acceptable`, read off a status, not a judgment): the receivers' parts.

## Offers
- `allowed` (an `Ask`: the record's named fields, its opened preimage, its flow's state and judged prefix, the `Checks`, the `Context`) → `Allowance`, the first rule broken (internal module `chain`; a key's deletion read by `deletion`).
- `timely` (an `Ask`, the acceptance time): TimeOK. `effectOf` (an `Ask`): Eff(r), the changes a Core record makes, the same in the Core's intent and the monitor's fold.
- `judge` (a `Reading`: the placed record, what opening its preimage gave or another writer's verified body, the key sets, the versions' windows, the prefix) → `Ruling`: the flow entry with its verdict and outcome, the row J0–J13 or J0r, whether counted; or a wait (internal module `judgment`).
- `resetFinding` (a reset boundary's body, its flow's state before it, the `Checks`, the `Context` with its `reset`: `ResetContext`, the acceptance time) → `ResetFinding`: verdict, outcome and `reset-wire`'s fault (internal module `reset`), which the monitor runs before placing a reset and `judge` again.
- `fold` (state, `Envelope`, `Changes`, `Finding`) → the state; `emptyState`; `abandonedFamily` (a bundle's envelope and changes) → the family an abandonment of its op drops, for the Core's intent and `effectOf` alike (internal module `fold`).
- `ruleSchemas`: `flowState`, `changes`, and `contents`, each Core kind's preimage content (internal module `evidence`).
- `tokenRules`, by kind of token:
  - `client` (internal module `client`): `start` (a client's start's evidence, a digest) → its op id (OpIdOf) and evidence elements (Elems), or why not, for the Core to derive them as the rules check them; `within`, whether its evidence's times hold an acceptance time, as TimeOK reads them; `lifetimeMs`, the longest a client's own token lives from its start: 15 minutes, a constant the Core narrows within..
  - `idToken` (internal module `id-token`): `cHash` (a code's SHA-256 digest) → an ID token's `c_hash`, its left half, for an ID token of an algorithm of SHA-256 (A21).
  - `bundle` (internal module `chain`): `effect` (a bundle's `via`, root and tokens' frames) → its changes, as `effectOf` gives them, for the Core's intent to take as is.
- `./testing`: `coreRecords` (a digest) → a Core writer's records made from evidence given, unsigned here, laid out as the rules read them: a first key, a key added, a key deleted, an approval, a person's start and a bundle, an op's abandonment, and a client's start naming its registry version, its op and elements derived as `tokenRules.client.start` derives them (`CoreRecords`, `Written`, `Continued`, `Ceremony`, `Approved`), for a harness writing on the log as a Core writer would.
- Types: `Ask`, `Named`, `Allowance`, `Checks`, `Context`, `RuleTimes`, `ClientAt`, `ClientEvidence`, `StartOf`, `Reading`, `Opening`, `Window`, `Ruling`, `Row`, `FlowRecord`, `FlowEntry`, `FlowState`, `Changes`, `Envelope`, `Finding`, `RecordKind`.

## Invariants
- Pure: no I/O, clock, randomness, crypto or state. A record's fields, its flow's judged prefix (the entries from position 1 and the state they fold to) and the caller's functions in; a value out. A caller's error of shape (a Core record without its opening) is a TypeError; the prefix's order, from position 1 with none skipped, is the caller's to keep: nothing here checks it.
- The one fold (PR-ONE-FOLD) changes the state only for a record verified or unsupported that took, and picks one effect by kind; nothing else changes a state. A reset is a monitor's boundary, which moves the key generation on only where it took.
- The verdict is the first row of the table it meets, in the table's order; the chain (J7) is checked before the time, and a forged row before an inherited hold (J9).
- A Core record is held to the ring of its writer's Core generation, the context's: a statement of another generation's ring is forged. A first key's key generation is the signed creation's.
- Another writer's record is judged with the body its signature verified (`signedRecord`); a role naming a kind it does not write is forged.
- What the rules hold no rule for is refused, never passed: a key change other than the first-key path, a sign-up's (F1) and a passkey-add, a person's op off a subject flow, and a client's start or bundle off its own flow.
- A check a client's record needs that the caller does not give (the client's record at its version, the evidence window, the self ceiling) leaves it unchecked: held, never verified nor forged.

## Depends on
- `transparency-wire`, `sdk-core-wire`, `continuation-wire`, `reset-wire` (the protocols); `zod`.

## Vocabulary
- state (S, M): a flow's live keys, approvals and families by the record that made each, its key generation and use-once marks.
- changes (e): what a record's writer left for the fold. entry: a judged flow position (envelope, changes, judgment, parent).
- root: the first-trust key's registration a chain rests on; a chain: the registrations from it down.
- verdict, outcome, row: the judgment table's (kernel-spec §6.1, §6.2).
