# completion

Internal module of `approvals`: an authorization's approval put on the subject's flow, and its completion.

## Responsibilities
- Registers the kind `approval` and the state owner `approvals`; decides, sends and takes in an approval as its owner; then signs the completion and seals it to the screen.

## Not here
- The frame, the owner rule, takers and abandonments: `transparency`. Whether the record holds: `authority-rules`.

## Offers
- `approvalKind`: no bundle, one stage, no records of its own and no resend: an orphan is marked and abandoned, never taken over. `approvalsOwner`: the state's `approvals` and `consumed`. `deciding` (KE-C01). `completionsOver` (`CompletionParts`) → the run of one completion. `part`.

## Invariants
- KE-C01 refuses where the statement's mark is set or its key is not live; its stage names the key's record as parent, carries the statement and assertion, and binds their digests and the code's; its changes are the approval (key, code's digest, client) and the statement's mark, as `authority-rules` reads the record.
- The op's id is `approval:` and the statement's hash, so a second completion of one statement is the same op.
- Nothing is decided for a statement past its expiry or one the Core's ring of this generation does not verify. A first stage refused `prevMismatch` closed the op with nothing on the flow: it is decided again. Deciding is tried four times while the flow is open, tending it between, so an orphan in the way is marked, abandoned and taken in within one `complete`.
- The completion is signed only after the owner's `took`; any other end answers `ended`. It names the wire version as the statement does. Its sealing's additional data is the statement's hash. A completion once made is kept on the record with its code's digest, and given again alike for that code alone; one not kept (a fault after `took`, a takeover, a lease ended) is never given.

## Depends on
- `transparency` (the contract, the kind's and owner's shapes), `transparency-wire` (the flow, the preimage), `keys` (`prepare`, `sign`, `seal`), `sdk-core-wire` (the completion's `typ`, HPKE's info); the package's `statement`.
