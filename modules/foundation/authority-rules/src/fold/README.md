# fold

Internal module of `authority-rules`: a flow's state and the one fold over it (kernel-spec §6.3, PR-ONE-FOLD).

## Responsibilities
- Owns a flow's state (S) and a record's changes (e), their schemas, and what one judged record does to the state.

## Not here
- Which changes a record makes, and its judgment: `chain` and `judgment`. Where the state is kept, and the position a take-in moves: the caller's.

## Offers
- `flowState`, `changes` (schemas), `FlowState`, `Changes`, `Envelope` (`Env(r)` with the record's id), `Finding` (verdict, outcome), `FlowEntry` (with the parent, for a start or a bundle `via`, and for a client's start `client`: its elements, version and key), `RecordKind`, `emptyState`, `acceptable`, `own` (an item by id).
- `fold` (state, envelope, changes, finding) → the state.
- `abandonedFamily` (a bundle's envelope and changes) → the family an abandonment of its op drops, by the name the fold gives it.

## Invariants
- An abandonment's family comes from the abandoned op's bundle entry's changes (read by `chain`'s `effectOf` from the prior), by `abandonedFamily` here: where the monitor could not read that bundle's preimage (J5, J6) they are empty, so the monitor names no family where the Core's intent names one (kernel-spec §6.3's contract 1 leaves this open).
- A record changes the state only when verified or unsupported and took; then one effect by kind: a denial revokes, an abandonment drops its family, an erasure boundary and a reset boundary move the key generation on, a confirmation and a tombstone change nothing, any other adds its changes.
- Only an op's last stage adds; an earlier stage (a start) changes nothing.
- A key, an approval or a family is added only while what it hangs from is live; each is named by the id of the record that made it, its position and acceptance time from the envelope.
- Revoking `x` takes `x` and every item whose chain holds it, `x` gone or not. Deleting a key `x` (`removeKey`, DelDrop, V24) takes `x` and the families whose root key (their chain's last) it is, alone: the keys it approved and its approvals stay; no key `x`, no change. A new key generation keeps the use-once marks and nothing else; an abandonment keeps them too.
- A family's rotation goes up by one per refresh that took; its acceptance time stays the one it was made at.
- An id finds an item only as the state's own entry, never a name every object inherits (`toString`, `__proto__`); the schema reads a state's items entry by entry, so every own id reads back, and a list in their place is refused.
- A reset is the monitor's boundary record (V22), not a Core record's change: no change carries one, and it takes only as `reset`'s rule finds it.

## Depends on
- `transparency-wire` (the kinds, verdict and outcome words); `zod`.

## Vocabulary
- item: a key, an approval or a family. chain: the registrations from the root first-trust key down to the item's own key.
- use-once mark: a statement's (`statement:<sid>`) or a code's (`code:<approval>`), set by the last stage that used it.
