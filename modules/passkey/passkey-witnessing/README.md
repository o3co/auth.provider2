# passkey-witnessing

## Responsibilities
- Keeps the passkey witness's mark for key generations, as `passkeys`' `passkeyWitnessing` asks, over the one witness composed (`passkey-witness`' `passkeyWitnesses`).

## Not here
- When a mark is set or withdrawn, and what is decided with it: `passkeys`, whose `settle` asks. Who runs `settle`: whoever took in an end of a key change, as `passkeys`' card says.
- The witness's promises: `passkey-witness`. Where the mark is kept: the witness composed, an outside ledger's (`passkey-witness-http`) or the provider's own (`users-local`).

## Offers
- Composition definition only: a contribution to `passkeys`' `passkeyWitnessing`.
  - `marked` (subject): whether the witness reads a mark, whichever generation set it.
  - `mark` (subject, generation): enrolls the generation's token, and ends with a mark of that generation or a later set: one of a generation before is withdrawn by its token and the enroll made again, 3 times at most, then it is unavailable.
  - `withdraw` (subject, generation): removes, by its token, a mark of a generation before the one given, then reads again and removes one landed meanwhile, 3 times at most, then is unavailable.
- It comes with `passkeys`, through `combinations`, whichever witness is composed (`passkey-witness-http`, or `users-local`'s); a composition of `passkeys` with no witness so refuses boot here.

## Invariants
- A mark's token is `generation-` and its generation, the same for every mark of it, so a mark sent again answers alike. A mark of a token in another form, or of a generation past a safe integer, is unavailable to `mark` and `withdraw`, which remove nothing then. Marks a 0.x ledger set by random tokens are not carried over: auth.provider2 is another product, its ledgers its own.
- A generation that is no whole number at or above zero is a `TypeError`.
- A witness that cannot answer is unavailable, passed on as it is, never a refusal or a default.
- It holds nothing per subject: a mark of a generation before, set after a `withdraw` returned, stands until a `withdraw` of a later generation, which `passkeys`' `settle` asks once it reads the keys again.
- Boot is refused without exactly one witness composed.
- It holds nothing in process, so it is safe on many instances.

## Depends on
- `kernel`, `passkeys` (the witnessing point), `passkey-witness` (the witness)

## Vocabulary
- generation: the subject flow's key generation, which an erasure boundary moves on.
