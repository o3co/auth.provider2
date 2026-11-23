# transparency

## Responsibilities
- Holds the Core's side of the transparency log: the contract the Core's writers take, the log's axis an adapter provides, and the intent frame, one per conditional flow, which every writer's op shares (internal modules `frame`, `driver`).
- Owns the frame's store interface and its needs, and the frame store over `store` a wiring builds (internal module `frame-store`).

## Not here
- The verdict, the fold and a flow's state: `authority-rules`. The words, records, receipts and op ids: `transparency-wire`.
- What an op's changes and records mean, and its output (tokens, a key confirmed): its writer's, registered as a kind of operation. What a state owner keeps: its own, registered as an owner of state.
- Appending, sealing, digests and judgments: the log's adapter. Signing tokens: the owners of `prepare` and `sign`.
- A client's flow (client_credentials), whose intent's unit is the op.

## Offers
- `transparency`: `decide` (KE-C01, with its kind's records), `send` (KE-C02), `rebase`, `step` (KE-C04), `tend` (KE-C04, C14, C10 and C09 for an idle replica), `changeHeld` (a writer's records, changed while no intent is open). `Refused`, `End`, `Ending`.
- `transparencyLog`, the log's axis: the writer, `digest`, `append`, `head`, `at`. `Stage`, `Placed`.
- `frameStore`, the frame's store interface (`FrameRead`, `PartRecord`, `PartNext`), and `frameStoreNeeds`: never evicted, survives a crash and a failover, reads confirmed, authenticated. `FramePart`.
- `operationKinds` (`OperationKind`: bundle or not, its parts and records, its end's writes, a taker's resend) and `stateOwners` (`StateOwner`: the state's fields it holds, its records, records → fields, state → records), keyed by name.
- `BundleSigning`: the token endpoint's `prepare` before a bundle's append and `sign` after its receipts, implemented by their owners. `Deciding`: a writer's part of KE-C01.
- For wirings alone: `frameStoreOver`, the frame store over `store`, which `transparency-store` builds; `frameParts`, each part's place, which its owner's wiring contributes.
- `./testing`: `frameStoreContract`, the contract test of every frame store.

## Invariants
- A flow has one frame: its applied position, the generation that sealed it, and its one intent. Every event writes once, held to all it read: the frame, every state owner's records, and the intent's kind's records.
- The owner rule (kernel-spec §5.1): owner ≜ pending ∧ by this replica ∧ its lease holds, judged on the store clock; an owner's write is refused past its lease's end. A lease's end writes nothing: the intent and its changes stay.
- A Step takes in the next record alone, once judged, applying `fold` once on the state the owners' records hold, whoever wrote the record; only the intent's end depends on its kind (the end-of-intent table).
- A kind's records (a reservation) are decided, ended and changed only with the frame held: `changeHeld` writes nothing while an intent is open, so being appended is shown by the frame alone.
- Boot is refused unless every field of a flow's state has one owner, and every part a registration names is bound to a place.

## Data
- Each conditional flow's frame, in its wiring's space with no expiry; it holds an op's changes (`eff`) until the op ends.

## Depends on
- `kernel`, `transparency-wire`, `authority-rules`; `store` (its types alone, for the frame store a wiring builds); `zod`.

## Vocabulary
- frame: a flow's applied position, its seal and its intent. intent: the op in flight on a flow (`it[f]`). owner: the replica whose lease on the intent holds. orphan: a pending intent whose lease ended.
- part: a writer's or a state owner's records, joining a flow's one write. kind of operation: a writer's registration. owner of state: a registration of fields of a flow's state.
- end: how an op ended: took, didNotTake, held, abandoned (its abandonment closed it) or refused (its owner closed it).
