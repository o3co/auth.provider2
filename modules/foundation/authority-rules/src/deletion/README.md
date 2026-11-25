# deletion

Internal module of `authority-rules`: a key's deletion (`passkey-manage`, V24; kernel-spec's note on a key's deletion), as a key change's `delete` variant.

## Responsibilities
- Reads a key change of variant `delete` on the state just before its record, and tells whether its evidence deletes the key it names, and which key that is.

## Not here
- Where the record sits on its op, the passkey-manage's use, the envelope's digests, its times and its changes: `chain`, which asks it. How the key's deletion folds (DelDrop): `fold`. Confirming or denying a deleted first-trust key: the monitor's writer records, not these rules.

## Offers
- `deletionOf` (`DeletionAsk`: the state, the caller's checks and context, the record's parent, evidence and credential) → `Deletion`: why not, or the passkey-manage, the body, its sid and times, and the deleted key's registration id.

## Invariants
- Its evidence is, in its one order: the passkey-manage (by the writer generation's ring), the approving key's assertion over it, the screen's continuation.
- The approving key (`parent`) is live and asserts the passkey-manage; the continuation's stage is `delete` (a rename's also names a credential), signed by the passkey-manage's E_sig over `continuation.of("delete", …)` of its digest and the body's.
- The body is the canonical text of `{ credential_id }` alone, of the wire's shape (`continuation.bodies.delete`), and names the record's key (`content.credential`), which is live: the approving key or another.
- A key is left after it: the last key goes by a reset, a denial or an erasure alone (KP-22, proposal (i), O10).
- Live is read on the state just before the record (`StateOf(f, p)`), as `chain` gives it.

## Depends on
- `sdk-core-wire` (`continuation.of`, `continuation.bodies.delete`, `canonicalText`); the package's `evidence` and `fold`.
