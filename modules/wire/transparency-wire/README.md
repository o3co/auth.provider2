# transparency-wire

## Responsibilities
- Holds the contract of the transparency log, which the log and the monitor hold and the Core's writers, the receivers and their companions follow: the words, the schemas of what each side signs, sends or reads, and the inputs a token's digest and a preimage's sealing cover, from one place.

## Not here
- Signing, sealing, verifying, and the log's and the monitor's checks: each side's own.
- The verdict and fold rules, and the schemas of a flow's state and of a preimage's content: `authority-rules`.
- The Core's intents, leases and applied positions: the Core's `transparency`.
- A registry version's body: `registry-wire`. A config version's body: not this wire's.
- How people's keys sign a stop instruction, a restart approval or a change of their signer set: not yet decided; their `typ` claims no JWS.

## Offers
- `speaks`: the wire versions, each object's `v`. `logTyps`: the `typ` of each signed object: receipt, judgment, checkpoint, status, status reasons, stateOf, each signed record body, and the callback's proof.
- `recordKinds`: the record kinds by writer role (`core`, `monitor`, `publisher`, `human`, `log`). `flows`: a flow's `units` and the `unconditional` one (`client`).
- `appendRefusals`: the log's refusals. `judgments`: `verdicts` and `outcomes`. `statusWords`: `shardStates` and `denyReasons`.
- `tokens`: the receipt claim `txr`, the `frames`, `parse` (text), the one JSON reading, `digestInput` (header text, claims text): what a token's digest covers, `ecThumbprintInput` (a P-256 JWK): `esig`'s RFC 7638 input, and `checks`: the frames a receipt check reads and the faults of R16–R18. `sealing`: the HPKE suite, `info` and `aad` (flow, op, stage) of a preimage.
- `signers`: the generation flow's counts. `opIds`: `stop` (generation) and `abandonment` (op, attempt).
- `schemas`: `appendRequest`, `appendAnswer`, `record`, `receipt`, `judgment`, `checkpoint`, `status`, `statusReasons`, `stateOf`, `preimage`, `recordRef`, `signerSet`, `bodies`, each record body no Core writer writes, `signedRecord`, such a record read with its verified body, `setSigned`, what a signer set signs (JWS General JSON), and the callback's `callbackHeader` and `callbackProof` (A38) and an ID token's `idTokenEvidence` (`esig`, `apr`).
- Types: `AppendRequest`, `AppendAnswer`, `LogRecord`, `Receipt`, `Judgment`, `Checkpoint`, `Status`, `StatusReasons`, `StateOf`, `Preimage`, `RecordRef`, `SignerSet`, `Writer`, `Flow`, `Verdict`, `StageOutcome`, `ReceiverKey`, `ReceiptFault`, `CallbackFault`, and the receivers' inputs `ReceiptCheck` (R16, R17) and `CallbackCheck` (R18).

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build by them; no I/O, clock, randomness or state. Every schema refuses an object whose `v` (where it has one) is not one `speaks` names, and a field it does not know, but in the `ext` of a status and a checkpoint: there the later stages add their fields without a new version, and a reader ignores a name it does not know.
- A record names its writer role's kinds alone. A Core writer's record carries its preimage sealed to each key of the monitors' set and, once committed, each ciphertext's hash and the key set's version the log checked; any other writer's carries its signed body. A `monitor` flow's id is its shard's.
- A conditional flow's append names the previous position, the record's position being one past it; an unconditional flow's names none.
- For an id already accepted with the same content, the log answers the original receipt before it checks the previous position, so `prevMismatch` says the record is not on the log and never will be; the same id with other content is `sameIdOther`.
- A bundle's append names one digest per token, a frame once, and is answered one receipt per token, in order. `keyNotInSet` comes with the shard's key set where it has one.
- A status carries ids alone, never a reason; the reasons go apart, for operators. A checkpoint always carries its not-accepted ids, even none, and the forged among them, each with its writer's generation: each is an id the monitor's signed judgment says `forged`, and the log stops those generations in the step it accepts the checkpoint.
- A signed body must match its record's envelope (`signedRecord`): an erasure boundary's and a tombstone's name its flow, op and previous position, a stop's op is derived from its generation, a restart names its previous position.
- A signer set's version only grows per purpose; a reader takes none older than the one it holds. A stop instruction is signed by one key, a restart approval by two of three or more. The install approval names no previous position, generation nor evidence.
- A token's digest is made from its texts, read by `parse`, which refuses a key named twice at any depth and a number past a double; no reader digests a token another way.
- A stateOf gives every position's result, from 1 to its position.
- A callback's proof is ES256 under E_sig, its header carrying the key; its `code_hash` is the code's whole UTF-8 SHA-256 (not OIDC's `c_hash`), its `iat` the device's clock, which no freshness rests on. `esig`'s input takes a P-256 key of exactly `crv`, `kty`, `x`, `y`, each coordinate 32 bytes in 43 canonical characters and the two a point of the curve.
- Digests are SHA-256, base64url; times are milliseconds since the epoch, but a proof's `iat`, in seconds.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- verdict (判定): `verified` 確かめた, `forged` 不正, `held` 保留, `unsupported` 根拠が足りない. outcome (成否): `took` 成った, `didNotTake` 成らなかった; apart from the kind `noEffect` (効かなかった).
- record (記録), flow (流れ), position (流れの位置), shard, `n` (通し番号), acceptance time `acceptedAt` (受け付けの時刻), op (操作), stage (段).
- watermark (W_s): the highest `n` the monitor judged and the log accepted the checkpoint of. not-accepted ids, `deny` (受けない一覧).
- generation (Core の世代), stop instruction (停止の指示), restart approval (再起動の承認), install approval (導入の承認), Core ring key record (Core の ring の鍵の記録), signer set (署名の組).
- key set (鍵の組), preimage (原像), plaintext digest (平文の digest), ciphertext hash (暗号文の hash), receipt (受領証), abandonment (放棄), evidence (証拠の束), root (根).
