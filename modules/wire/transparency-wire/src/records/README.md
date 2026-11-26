# records

Internal module of `transparency-wire`: a record and its append: what a writer sends, what the log answers and commits, a Core writer's preimage and its sealing, and the op ids.

## Responsibilities
- Holds a record to its writer role, its kind, its flow and its stage, in the append request and the committed record alike, and holds the log's answer to an append.
- Holds the field forms the other internal modules' schemas are written in, so each is spelled once.

## Not here
- The words (the kinds, the flows, the frames): `words`. The signed bodies of the records no Core writer writes, and such a record read with its body: `signed-bodies`. Receipts: `receipt-gate`.
- A preimage's content by kind: `authority-rules`.

## Offers
- `appendRefusals`; `opIds` (`stop`, `reset`, `abandonment`); `sealing` (the HPKE suite, `info`, and `aad` of a flow, an op and a stage).
- Schemas: `appendRequest`, `appendAnswer`, `record` (a written record, or the log's `tick`), `preimage`, `recordRef`; for the modules built on it, `written`, `writer`, `keySet`, `approvalDigests`, `keyChangeDigests`.
- Field forms: `v`, `id`, `recordId` (a record's id: `id` but never `__proto__`, well-formed UTF-16, and at most 63 bytes in UTF-8), `count`, `ordinal`, `digest`, `base64url`, `flow`, `ecKey` (a P-256 public key), `keyed` (a key with its `kid`); `coreKinds`.
- Types: `AppendRequest`, `AppendAnswer`, `LogRecord`, `Preimage`, `RecordRef`, `Writer`, `Flow`.

## Invariants
- A record's id is never `__proto__` where the wire carries the record's own id: a record, a tick, the log's accepted answer, a receipt, a judgment, a stateOf's results, and the checkpoint's and the status's id lists and reasons. A flow's state names its items by record ids and a store refuses that key, so a log naming one is off its form: such a record is not there, and is never named in a checkpoint, a status or a judgment.
- A record's id, where the wire carries it, is well-formed UTF-16 (no lone surrogate: a store refuses one, and a refresh token's base64url of its UTF-8 would not give it back) and at most 63 bytes in UTF-8: a refresh token is a family's id (its bundle record's) in base64url beside a 43-character secret, within the Front wire's `refreshToken` of 128 characters (front-core-wire). Owner, 2026-11-26.
- A reference to a record (a preimage's root or parent, a confirmation's registration) stays `id`: one no record can have dangles and is judged so. Any other `id` (a flow's, a key's, an op's, a shard's) may be `__proto__`.
- Only a reader that holds what it reads to these forms is kept from such a record: a log adapter that does not, the Core's take-in trusting it, is not.
- A record names its writer role's kinds alone.
  - A Core writer's record carries its preimage sealed to each key of the monitors' set and, once committed, each ciphertext's hash and the key set's version the log checked; any other writer's carries its signed body.
  - A `monitor` flow's id is its shard's.
  - A Core writer's op id is never a reset's or a stop's, and `abandonment:` goes with an abandonment alone; any other writer's plaintext digest is its signed body's payload's SHA-256.
- A conditional flow's append names the previous position, the record's position being one past it; an unconditional flow's names none.
- For an id already accepted with the same content, the log answers the original receipt before it checks the previous position (`prevMismatch`: never on the log); the same id with other content is `sameIdOther`.
- A bundle's append names one digest per token, a frame once, and is answered one receipt per token, in order. `keyNotInSet` comes with the shard's key set where it has one.

## Depends on
- `words`, `text` (`canonical`, `unique`); `zod`.
