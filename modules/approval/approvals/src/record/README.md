# record

Internal module of `approvals`: a statement's record, its shape and its reads, which the package's other internal modules share.

## Responsibilities
- Holds the record's shape, and reads a record kept by the store as that shape.
- Reads what a record and its statement carry: the completion kept whole, the creation a sign-up's step answered, the statement's items and issue time, its use-once mark, and the record's end.
- Says whether a statement verifies by the Core's ring of this generation.

## Not here
- Writing a record: each internal module writes its own fields through the store (`statement` issues and uses, `continuation` takes numbers and keeps answers, `completion`, `key-change-completion` and `passkey-completion` keep their completions), as Data names.

## Offers
- The record's shape: `StatementRecord`, `recordOf` (the store's value) → the record, `stored` (a record) → the store's value.
- `completionIn` (a record) → the completion it keeps, where it keeps one whole. `creationIn` (a step's answer) → the creation a sign-up's step answered; none for a refusal.
- `itemsIn` (a statement, its purpose) → its items; none for `itemless` purposes (passkey-add, passkey-manage). `issuedAtOf` (a statement) → its signed `iat`, in ms. `statementMark` (a statement's id) → its use-once mark, as `authority-rules`' fold names it.
- `keptPastS`, the 60 seconds a record outlives its statement, and `recordEnd` (a record) → when it is gone.
- `current` (the ring's verifying, a statement) → whether this generation's ring verifies it.
- Helpers the internal modules share: `sha256` (base64url), `wireVersion` (the latest `sdk-core-wire` speaks, which the Core writes).

## Invariants
- A record of another shape is read as a store that cannot tell: unavailable. Reading enforces nothing more: each caller judges state, expiry and the ring as its own rules say.

## Data
- Each statement's record: its purpose, bytes, the screen's keys, how far it went, the subject, credential and assertion that used it, the last continuation (its body as received, up to 8192 bytes, and signature; a sealed one's body hash alone) and its step's answer (a sealed list's up to about 60 kB), and the completion.
  - Written by `statement` (issued, used, a T's sign-up's subject, a completion gone out), `continuation` (the continuation's number, body, signature, hold and answer; a T's sign-up begun), `completion` (an authorization's completion, its code, the approval's record), `key-change-completion` (a key change's completion; a T's sign-up credential) and `passkey-completion` (a passkey-add's and a passkey-manage's completions).

## Depends on
- `sdk-core-wire` (the statement's member shape, `typ`, versions), `keys` (the ring's verifying, by type), `kernel` (unavailable); `zod`.
