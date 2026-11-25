# transparency

## Responsibilities
- Holds the Core's side of the transparency log: the contract the Core's writers take, the log's axis an adapter provides, and the intent frame, one per intent unit, which every writer's op on it shares (internal modules `frame`, `driver`).
- Owns the frame's store interface and its needs.

## Not here
- The verdict, the fold and a flow's state: `authority-rules`. The words, records, receipts and op ids: `transparency-wire`.
- What an op's changes and records mean, and its output (tokens, a key confirmed): its writer's, registered as a kind of operation. What a state owner keeps: its own, registered as an owner of state.
- Appending, sealing, digests and judgments: the log's adapter. Signing tokens: the owners of `prepare` and `sign`.
- The frame store over the store, and the parts' places: `transparency-frames`, which a wiring builds.

## Offers
- `transparency`: `decide` (KE-C01, with its kind's records), `send` (KE-C02), `rebase`, `step` (KE-C04), `tend` (KE-C04, C14, C10 and C09 for an idle replica), `changeHeld` (a kind's records, changed while no intent is open), `reset` (an embedder's instruction handed to the log: its `ResetAnswer`), `receiptOf` (a placed stage's answer again, placing none). `Refused`, `End`, `Ending`. A writer refused `open` or `notReady` tends the flow and decides again.
  - On a client's flow, each op is its own unit: `decide` answers the head it looks on from, appends name no previous position, `step` names the op (`own`), and `tend` tends the first 64 open ops the flow's record lists, moving them to its back. Each replica tends every client flow its frame store lists (`clientFlows`) every `tending`, so an op whose owner fell is closed though no writer asks of its flow again.
- `transparencyLog`, the log's axis: the writer, `digest`, `append` (after a previous position, or none on an unconditional flow), `head`, `at`, `of` (what the flow holds of an op: `OpOnFlow`), `reset` (places a reset boundary). `Stage`, `Placed`.
- `frameStore`, the frame's store interface (`IntentUnit`, `FrameRead`, `PartRecord`, `PartNext`, `Json`), and `frameStoreNeeds`: never evicted, survives a crash and a failover, reads confirmed, authenticated. On a client's op, a read holds its flow's record and a write may set it and drop the frame; `flowRecord` reads it alone, `clientFlows` lists the flows holding one, page by page, where the store lists them.
- Operator section: `lease` (default `5s`) and `tending` (at least `1s`, default `30s`), how often a replica tends client flows.
- `operationKinds` (`OperationKind`: bundle or not, its parts and records, its end's writes, a taker's resend) and `stateOwners` (`StateOwner`: the state's fields it holds, its records, records → fields, state → records), keyed by name.
- `BundleSigning`: the token endpoint's `prepare` before a bundle's append and `sign` after its receipts, by their owners. `Deciding`: a writer's part of KE-C01.
- `./testing`: `frameStoreContract`, the contract test of every frame store, a client's flow's record and a dropped frame included; `memoryFrames` and `logBook`, a frame store and a log in memory.

## Invariants
- An intent unit (V17: a subject's flow, or one op of a client's) has one frame: its applied position, the generation that sealed it, and its one intent. Every event writes once, held to all it read: the frame, every state owner's records, and the intent's kind's records.
- The driver runs a subject's flow, and a client's ops each alone; an event on any other flow, or naming no op of a client's, is refused (`notSubject`).
- A client's op holds no state: nothing is folded, its own records are taken in past other ops' unjudged, and only an `abandoned` refusal of its append closes it without a record (that stage is never placed); on any other its owner does nothing, and the op is abandoned once its lease ends (kernel-spec §5.1). It is decided once, whatever its end: its frame, its stages or abandonments on the log, or its flow's record where it ended with none, refuse it (`ended`).
- Whether an op's last stage is on the flow, and how many abandonments of it are, is read from the log (`of`), never kept in the frame: the answer holds whatever ops came between.
- The owner rule (kernel-spec §5.1): owner ≜ pending ∧ by this replica ∧ its lease holds, judged on the store clock; an owner's write is refused past its lease's end. A lease's end writes nothing: the intent and its changes stay.
- A Step takes in the next record alone, once judged, applying `fold` once on the state the owners' records hold, whoever wrote the record; only the intent's end depends on its kind (the end-of-intent table). A replica with no registration of an open intent's kind takes in, claims and ends nothing of it.
- An end its live owner gives output for (`owner`, `took`) is answered once its write committed. A writer's `eff` is `effectOf` of its op's last stage's record, taken in with that record alone (a start changes nothing); a family an abandonment drops is `authority-rules`' `abandonedFamily`.
- A kind's records (a reservation) are decided, ended and changed only with the frame held, never in the store directly: `changeHeld` writes nothing while an intent is open, so being appended is shown by the frame alone.
- Boot is refused unless every field of a flow's state has one owner, and every part a registration names is bound to a place.

## Data
- Each intent unit's frame, in its wiring's space with no expiry; it holds an op's changes (`eff`) until the op ends. A client's op's frame is dropped once its op ends, in the end's write: no store evicts it.
- Each client's flow's record: the ops decided on it and not yet ended, in the order its tending goes round them, and the ops closed with nothing of them on the log; written in the same write as each op's frame, and by a turn of `tend`.

## Depends on
- `kernel`, `transparency-wire`, `reset-wire`, `authority-rules`; `zod`.

## Vocabulary
- unit: what one frame is of. frame: a unit's applied position, its seal and its intent. intent: the op in flight on a flow (`it[f]`). owner: the replica whose lease on the intent holds. orphan: a pending intent whose lease ended.
- part: a writer's or a state owner's records, joining a flow's one write. kind of operation: a writer's registration. owner of state: registered fields of a flow's state.
- end: how an op ended: took, didNotTake, held, abandoned (by its abandonment) or refused (by its owner).
