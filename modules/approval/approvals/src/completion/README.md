# completion

Internal module of `approvals`: an authorization's approval put on the subject's flow, and its completion.

## Responsibilities
- Registers the kind `approval` and the state owner `approvals`; decides, sends and takes in an approval as its owner; then signs the completion and seals it to the screen.

## Not here
- The frame, the owner rule, takers and abandonments: `transparency`. Whether the record holds: `authority-rules`.
- A key change's completion (`key-change-completion`). A passkey-add's and a passkey-manage's (`passkey-completion`).

## Offers
- `approvalKind`: no bundle, one stage, no records of its own and no resend: an orphan is marked and abandoned, never taken over. `approvalsOwner`: the state's `approvals` and `consumed`. `deciding` (KE-C01). `completionsOver` (`CompletionParts`) → the run of one completion, `complete`:
  - `complete` (hash, code) → the completion sealed to `eEnc` (HPKE's `enc` and ciphertext) and the approval's record's id on the flow (the code's chain's root), its `recordRef` (`ref`, an ID token's `apr`) and acceptance time (`acceptedAt`, its `auth_time`); or refused.
- `completionOf` (the build context) → `complete`; `completionTakes`, which its package names among its own takes.

## Invariants
- KE-C01 refuses where the statement's mark is set or its key is not live; its stage names the key's record as parent, carries the statement and assertion, and binds their digests and the code's; its changes are the approval (key, code's digest, client) and the statement's mark, as `authority-rules` reads the record.
- The op's id is `approval:` and the statement's hash, so a second completion of one statement is the same op.
- Nothing is decided for a statement expired, or one this generation's ring does not verify. A first stage refused `prevMismatch` closed the op with nothing on the flow: it is decided again. Deciding is tried four times while the flow is open, tending it between, so an orphan in the way is marked, abandoned and taken in within one `complete`.
- The completion is signed only after the owner's `took`; any other end answers `ended`. It names the wire version as the statement does. It is sealed under `sdk-core-wire`'s `completionAad` of `authorization` and the statement's hash. One made is kept with its code's digest and the approval's record id, given again for that code alone; one not kept (a fault after `took`, a takeover, a lease ended) never is.

## Depends on
- `transparency` (the contract, the kind's and owner's shapes), `transparency-wire` (the flow, the preimage), `keys` (`prepare`, `sign`, `seal`), `sdk-core-wire` (the completion's `typ`, HPKE's info and `completionAad`), `issuer`, `kernel` (the build context); the package's `record`, and the contract's `approvalPart`.
