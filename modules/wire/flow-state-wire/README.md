# flow-state-wire

## Responsibilities
- Holds how a receiver reads a flow's applied state, the one a stateOf carries signed: the parts of it a receiver may rest on (a subject's keys' credential ids and its key generation), in this wire's words, from one place for the login screen, an embedder and whoever folds the state.

## Not here
- The stateOf itself, its signer set and its `typ`: `transparency-wire`.
- The state's other parts, the fold that makes it and its schema: `authority-rules`, which holds its state to give these reads.
- Verifying a stateOf's signatures, and what a receiver concludes from the reads: each receiver.

## Offers
- `credentialsOf` (a state): the credential ids of the keys it holds, each once, in its order; none where the state does not read so, apart from an empty list.
- `keyGenerationOf` (a state): its key generation, a whole number from 0; or none.

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that read by them; no I/O, clock, randomness or state. It depends on no package of the workspace (G2, G6).
- A state is taken as unknown and read as its JSON names the parts: `keyGeneration`, and `keys` with one own entry per live key naming its `credential`. Every other part is left unread, so a state gaining a part changes no read.
- An entry is read by its own key (`__proto__` too), never one inherited; an entry naming no credential id makes the whole read none, never a shorter list.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- applied state (適用ずみの状態): a flow's state after every record up to a position, as the fold made it. credential id: a passkey's WebAuthn id, base64url. key generation (鍵の世代): the count of resets and erasures that took.
