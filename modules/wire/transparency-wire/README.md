# transparency-wire

## Responsibilities
- Holds the contract of the transparency log, which the log and the monitor hold and the Core's writers, the receivers and their companions follow: the words, the schemas of what each side signs, sends or reads, and what a token's digest and a preimage's sealing cover.

## Not here
- Signing, sealing, verifying, and the log's and the monitor's checks: each side's own.
- The verdict and fold rules, and the schemas of a flow's state and of a preimage's content: `authority-rules`.
- The Core's intents, leases and applied positions: the Core's `transparency`.
- A registry version's body: `registry-wire`. A config version's body: not this wire's.
- How people's keys sign a stop instruction, a restart approval or a change of their signer set: not yet decided; their `typ` claims no JWS.

## Offers
- `speaks`: the wire versions, each object's `v`. `logTyps`: each signed object's `typ` (receipts, judgments, checkpoints, status and its reasons, stateOf, record bodies, the reset instruction, the callback's proof; internal module `words`).
- `recordKinds`: the record kinds by writer role (`core`, `monitor`, `publisher`, `human`, `log`). `flows`: a flow's `units` and the `unconditional` one (`client`) (internal module `words`).
- `appendRefusals`: the log's refusals, `abandoned` and `evidenceUsed` checked after `sameIdOther`, both marks kept without end (internal module `records`). `judgments`: `verdicts` and `outcomes`. `statusWords`: `shardStates` and `denyReasons` (internal module `judging`).
- `tokens`: the receipt claim `txr`, the `frames` (internal module `words`), `parse` (the one JSON reading, internal module `text`), `digestInput` (what a token's digest covers), `ecThumbprintInput` (`esig`'s RFC 7638 input), `checks` (R16–R18's frames and faults) (internal module `receipt-gate`). `sealing`: the HPKE suite, `info` and `aad` of a preimage (internal module `records`).
- `signers`: the counts of the generation flow's and the reset instruction's sets (internal module `signed-bodies`). `opIds`: `stop` (generation), `reset` (instruction id) and `abandonment` (op, attempt) (internal module `records`).
- `schemas`:
  - `appendRequest`, `appendAnswer`, `record`, `preimage`, `recordRef` (internal module `records`).
  - `signerSet`, `bodies` (each body no Core writer writes), `signedRecord` (such a record with its verified body) (internal module `signed-bodies`).
  - `judgment`, `checkpoint`, `status`, `statusReasons`, `stateOf`, `setSigned` (JWS General JSON) (internal module `judging`).
  - `receipt`, `callbackHeader`, `callbackProof` (A38) and `idTokenEvidence` (`esig`, `apr`) (internal module `receipt-gate`).
- Types:
  - `AppendRequest`, `AppendAnswer`, `LogRecord`, `Preimage`, `RecordRef`, `Writer`, `Flow` (internal module `records`).
  - `SignerSet`, `ReceiverKey` (internal module `signed-bodies`).
  - `Judgment`, `Checkpoint`, `Status`, `StateOf`, `Verdict`, `StageOutcome` (internal module `judging`).
  - `Receipt`, `ReceiptFault`, `CallbackFault`, and the receivers' inputs `ReceiptCheck` (R16, R17) and `CallbackCheck` (R18) (internal module `receipt-gate`).

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build by them; no I/O, clock, randomness or state. Every schema refuses a `v` not in `speaks` and an unknown field, but in a status's and a checkpoint's `ext`, which later stages extend and a reader ignores where it does not know a name.
- A token's digest is made from its texts, read by `parse`, which refuses a key named twice at any depth and a number past a double; no reader digests a token another way.
- Digests are SHA-256, base64url; times are milliseconds since the epoch, but a proof's `iat`, in seconds.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- record (記録), flow (流れ), position (流れの位置), shard, `n` (通し番号), acceptance time `acceptedAt` (受け付けの時刻), op (操作), stage (段).
- key set (鍵の組), preimage (原像), plaintext digest (平文の digest), ciphertext hash (暗号文の hash), receipt (受領証), abandonment (放棄), evidence (証拠の束), root (根).
