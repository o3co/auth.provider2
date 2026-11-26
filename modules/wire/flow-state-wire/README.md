# flow-state-wire

## Responsibilities
- Holds how a receiver reads a subject flow's applied state, the one a stateOf carries signed: the parts of it a receiver may rest on (its keys' credential ids and its key generation), in this wire's words, from one place for a receiver and whoever makes the state.

## Not here
- The stateOf itself, its signer set and its `typ`: `transparency-wire`.
- The state's other parts, the fold that makes it and its schema: `authority-rules`, which holds its state to give these reads.
- Verifying a stateOf's signatures, and what a receiver concludes from the reads: each receiver.

## Offers
- `credentialsOf` (a subject flow's state): the credential ids of the keys it holds, each once, as a set; none where the state does not read so, apart from an empty list.
- `keyGenerationOf` (a subject flow's state): its key generation, a whole number from 0; or none.
- Either read of another flow's state means nothing: a receiver reads a subject's stateOf alone.

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that read by them; no I/O, clock, randomness or state. It depends on no package of the workspace (G2, G6).
- A state is taken as unknown, as JSON gives it, and read as its JSON names the parts: `keyGeneration`, and `keys` (plain objects alone) with one own entry per held key naming its `credential` in canonical base64url. Every other part is left unread, so a state gaining a part changes no read.
- An entry is read by its own key, never one inherited; an entry naming no credential id, or a key `__proto__` (no record id is one: transparency-wire refuses it), makes the whole read none, never a shorter list.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- applied state (適用ずみの状態): a flow's state after every record up to a position took effect. held key: a key the state names at its position. credential id: a passkey's WebAuthn id, canonical base64url (one spelling, so ids compare as text). key generation (鍵の世代): the count of resets and erasures that took.
