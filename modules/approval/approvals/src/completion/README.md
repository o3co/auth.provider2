# completion

Internal module of `approvals`: an authorization's approval put on the subject's flow, and its completion; a key change's completion; and a passkey-add's.

## Responsibilities
- Registers the kind `approval` and the state owner `approvals`; decides, sends and takes in an approval as its owner; then signs the completion and seals it to the screen.

## Not here
- The frame, the owner rule, takers and abandonments: `transparency`. Whether the record holds: `authority-rules`.

## Offers
- `approvalKind`: no bundle, one stage, no records of its own and no resend: an orphan is marked and abandoned, never taken over. `approvalsOwner`: the state's `approvals` and `consumed`. `deciding` (KE-C01). `completionsOver` (`CompletionParts`) → the run of one completion, `complete`:
  - `complete` (hash, code) → the completion sealed to `eEnc` (HPKE's `enc` and ciphertext) and the approval's record's id on the flow (the code's chain's root), its `recordRef` (`ref`, an ID token's `apr`) and acceptance time (`acceptedAt`, its `auth_time`); or refused. `part`.
- `keyChangeCompletionsOver` → `completeKeyChange` (a used possession's hash, its path's purpose `first-key`, `passkey-add` or `sign-up`, what the change's record was given on the log): the `keyChange` completion of the key the possession names.
  - A sign-up's first keeps the possession's credential on its T (`signUp.credential`), unless the T kept another (`other`). Its possession's creation is the one its T's sign-up step answered, of basis `sign-up`, both records verified by this generation's ring (`creation` otherwise).
  - A possession of a sign-up's creation asked for another purpose is refused `creation`.
- `passkeyAddCompletionsOver` → `completePasskeyAdd` (a used passkey-add's hash, the assertion that used it as received, and, to make one, the creation its caller made for it): the `passkeyAdd` completion carrying that creation.

## Invariants
- KE-C01 refuses where the statement's mark is set or its key is not live; its stage names the key's record as parent, carries the statement and assertion, and binds their digests and the code's; its changes are the approval (key, code's digest, client) and the statement's mark, as `authority-rules` reads the record.
- The op's id is `approval:` and the statement's hash, so a second completion of one statement is the same op.
- Nothing is decided for a statement past its expiry or one the Core's ring of this generation does not verify. A first stage refused `prevMismatch` closed the op with nothing on the flow: it is decided again. Deciding is tried four times while the flow is open, tending it between, so an orphan in the way is marked, abandoned and taken in within one `complete`.
- The completion is signed only after the owner's `took`; any other end answers `ended`. It names the wire version as the statement does. It is sealed under `sdk-core-wire`'s `completionAad` of `authorization` and the statement's hash. A completion once made is kept on the record with its code's digest and the approval's record id, and given again alike for that code alone; one not kept (a fault after `took`, a takeover, a lease ended) is never given.
- A key change's completion is asked by its caller once its change took, which this module does not see. Its change is the key the possession's items name, never one the caller gives.
- One is made only for a used possession unexpired that the Core's ring of this generation verifies, in a form `sdk-core-wire`'s `keyChange` takes (else `form`): signed by the ring, sealed to the possession's screen under `completionAad` of the purpose and the possession's hash, kept with the purpose's digest. Past the statement's expiry none is made, after a change took too.
- Kept, it is given again alike for that purpose, with what the log gave as first asked; another purpose is `other`.
- A passkey-add's completion is made only for a passkey-add used by the same assertion, unexpired, that this generation's ring verifies, and a creation issued here for it: basis `passkey-add`, its hash as evidence, the subject that used it, the same screen's keys (else `creation`).
- It is signed and sealed under `completionAad` of `passkey-add` and its hash before anything is kept, then kept whole in one write from used: the first kept is answered to every call after, with or without a creation, whatever has lapsed since. Made twice at once, one creation is lost unseen.

## Depends on
- `transparency` (the contract, the kind's and owner's shapes), `transparency-wire` (the flow, the preimage), `keys` (`prepare`, `sign`, `seal`), `sdk-core-wire` (the completion's `typ`, HPKE's info and `completionAad`, `payloads.completions.keyChange`); the package's `statement`.
