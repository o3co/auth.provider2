# transparency-local

## Responsibilities
- Provides `transparency`'s log axis inside the Core (t0): each flow's records in its own store interface, positions counted by the store, acceptance times from the appending replica's kernel clock.
- Judges each record as it is placed (j0), running `authority-rules` with the Core ring's verification (`keys`), passkey assertions and keys' thumbprints (`webauthn`, every algorithm a passkey may be of) and SHA-256.
- Declares where that leaves the promise a log and a monitor outside the Core would hold.

## Not here
- The Core's intents, frames and Steps: `transparency`. The rules, the verdict and the fold: `authority-rules`. The words and forms: `transparency-wire`.
- A log, a monitor and receipts outside the Core: another adapter of the axis. Placing a reset's boundary record on an embedder's signed instruction, a monitor's: no port here takes one.
- The records' place: its wiring, which builds the store interface by `logStoreOver`.

## Offers
- Composition definition: the log axis (`transparencyLog`) and a stance (`promises`' `stances`).
- It is never the axis's default (`neverDefault`): a composition names it for `transparency`'s axis to compose it.
- `logStore`, its store interface (records by key, read, then written as one held to every version read), `logStoreNeeds` (never evicted, survives a crash and a failover, reads confirmed, authenticated) and `logStoreOver` (a store, a space, randomness, `where`, `refuse`), over `records`' records held across.
- Operator section `transparency-local`: `origin` (required), the one origin an assertion is judged for: where `webauthn.origins` lists several, an assertion made at another is judged forged; `code-lifetime` (default `10m`), `refresh-lifetime` (default `365d`) and `issue-window` (default `1m`), the rules' times. Each no shorter than the lifetime its issuer holds, so the rules never cut an issuance short.

## Invariants
- A conditional flow's append places after its head alone (`prevMismatch` else); an unconditional one's names none and places at the head. A previous position given otherwise is the writer's TypeError.
- An op's stage placed already is answered as first placed where the stage as named (each field, and its preimage's digest) is the same, `sameIdOther` where not, before the previous position is read.
- A record is placed in one write with the flow's head, its judged prefix and its op's stages, held to all it read: two appends after one position place one. After 8 lost races an append is `temporary`.
- A stage naming a version is the writer's TypeError: no publisher's flow is here to give its window.
- A record's shard is its flow, its `n` its position. It names the local key alone, `local`, its hash the plaintext digest; its writer names its replica, the image `transparency-local` and the Core generation `keys` signs as. The preimage is judged, then dropped.
- A record's acceptance time is the appending replica's clock, and the rules take no skew (ε is 0): a replica's clock must stay well under a second from the others' and the screen's, or an honest record is judged off its statement's times.
- Each record is judged once, as placed, on its flow's judged prefix, by the settings and keys of then; one changed later judges no record again. One the rules take is forged still where the credential of a root it names is no key passkeys holds for the flow's subject.
- A receipt, one per token or one, holds the wire's receipt, its issuer `transparency-local`, under `alg` `none`: unsigned.
- A digest is SHA-256 of the preimage's canonical JSON.
- It stands breaking `core-compromise-contained`, its reason naming it not recommended: the log and its judgment run in the Core, so a compromised Core places and judges its own records and nothing stops its generation.
- A stored record of another shape is unavailable, never none. It holds nothing in process, so it is safe on many instances.

## Data
- Per flow, in its wiring's space, kept without end: the head, the judged prefix, each position's record with its finding, and each op's stages (each with its digest as named) and abandonments.

## Depends on
- `kernel`, `transparency`, `transparency-wire`, `authority-rules`, `keys`, `webauthn`, `passkeys` (`publicKeyOf`), `promises`, `records`, `store`; `zod`. `passkeys` and `webauthn` must be composed beside it: it takes both.

## Vocabulary
- head: how many records a flow has. prefix: a flow's judged entries from position 1.
