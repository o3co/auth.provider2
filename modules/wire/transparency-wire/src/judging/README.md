# judging

Internal module of `transparency-wire`: what the monitor and the log give out about judged records: a judgment, a checkpoint, the status and its reasons, a flow's stateOf, and the JWS a signer set signs them in.

## Responsibilities
- Holds the monitor's verdicts and the outcome, and each object it or the log signs about them, to its schema.
- Holds an object a signer set signs to RFC 7515's JWS JSON General Serialization, so a reader counts the signatures against the set.

## Not here
- The judgment rules, the fold and a flow's state: `authority-rules`. The signer set and its counts: `signed-bodies`. Verifying the signatures: each side's own.
- The receivers' checks of a status: `receipt-gate`.

## Offers
- `judgments`: `verdicts` and `outcomes`. `statusWords`: `shardStates` and `denyReasons`.
- Schemas: `judgment`, `checkpoint`, `status` (its shards' watermark, generation and state, its not-accepted ids), `statusReasons`, `stateOf`, `setSigned`.
- Types: `Judgment`, `Checkpoint`, `Status`, `StateOf`, `Verdict`, `StageOutcome`.

## Invariants
- A status carries ids alone, never a reason (the reasons go apart, for operators). A checkpoint always carries its not-accepted ids, even none, and the forged among them (each a signed `forged` judgment) with their writers' generations, which the log stops in the step it accepts it.
- A stateOf gives every position's result, from 1 to its position.
- A `setSigned` object names each protected header once; each signature's header names `alg`, the object's `typ` and its key's `kid`.

## Depends on
- `records` (the field forms), `text` (`unique`); `zod`.

## Vocabulary
- verdict (判定): `verified` 確かめた, `forged` 不正, `held` 保留, `unsupported` 根拠が足りない. outcome (成否): `took` 成った, `didNotTake` 成らなかった; apart from the kind `noEffect` (効かなかった).
- watermark (W_s): the highest `n` the monitor judged and the log accepted the checkpoint of. not-accepted ids, `deny` (受けない一覧).
