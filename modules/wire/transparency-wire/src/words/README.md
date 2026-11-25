# words

Internal module of `transparency-wire`: the words the other internal modules name: the wire versions, each signed object's `typ`, the record kinds, the flows and the token frames.

## Responsibilities
- Holds the protocol's word lists, frozen, each word once, for the schemas, the signer sets and the receivers' checks to name.

## Not here
- Holding a record to its kind, its writer role and its flow: `records`. The receivers' frames and faults: `receipt-gate`. The signer sets' counts: `signed-bodies`.

## Offers
- `speaks`: the wire versions, each object's `v`. `logTyps`: each signed object's `typ` (receipts, judgments, checkpoints, status and its reasons, stateOf, record bodies, the reset instruction, the callback's proof).
- `recordKinds`: the record kinds by writer role (`core`, `monitor`, `publisher`, `human`, `log`). `flows`: a flow's `units`, and `unconditional`, the list of the flows whose append names no previous position (`client` alone).
- `frames`: the frames a bundle names its tokens by, which `tokens.frames` gives.

## Invariants
- A kind is one writer role's alone: the `human` kinds are the generation flow's, signed by people's keys, and the `log`'s is its empty commit (`tick`).

## Depends on
- Nothing.
