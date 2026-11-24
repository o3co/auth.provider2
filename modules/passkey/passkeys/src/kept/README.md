# kept

Internal module of `passkeys`: reading the keys a subject's flow holds, asserting by them, and settling after a key change.

## Responsibilities
- Answers `assert`, `publicKeyOf` and `settle` from the applied state and the credential records; moves counts on; tells removals and the witnessing.

## Not here
- Changing a reservation or a binding: the internal module `registering`. What a Step writes to the keys and the notices: the package's records (its owner of state).

## Offers
- `keptOver` (the frames, the credential store, the ceremonies, the verification, `transparency`, the witnessing, the removals) → the package's `Passkeys`. `keysHeld`, `credentialRecord`, `credentialOf`, `counted` and `stored`, for `registering`.

## Invariants
- Reads are of the applied state: a removal on the log but not taken in still reads active. A key is asserted only while its record binds its subject and keeps its details.
- `assert` moves the count on only over the record judged (`raced` otherwise).
- `settle` reads the keys, the notices the Steps wrote of each credential they took off (the latest 64), and what the last settle told of; it tells `passkeyRemovals` of each notice past that and drops the credential's details, notes each active key's record as once active, withdraws marks of generations before the current, and sets the mark while a key is held. It writes what it told of held to what it read; a write refused leaves the next settle to tell the same again.
- A `settle` that sets the mark reads the keys again after, and withdraws below a generation a boundary moved on meanwhile.
- Keys missing or behind what a settle told of (a generation or a notice before it) are a loss or a rollback: `settle` tells nothing and is unavailable.

## Depends on
- `kernel` (`Unavailable`), `webauthn` (the ceremonies' types), `transparency`; the package's contract and records.
