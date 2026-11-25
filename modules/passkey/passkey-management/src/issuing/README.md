# issuing

Internal module of `passkey-management`: the job of a first key's start that passed.

## Responsibilities
- Settles the subject's keys, and where it holds none picks the mail's address, writes the mail token, and sends the mail.

## Not here
- Whether the start passed, and its code: the start. The token's record: internal module `tokens`. The wording: `passkey-management-mail`. The mail's limits: `mail`'s sender.

## Offers
- `issuingOver` (passkeys' `settle`, `heldKeys`, users' reads, the token's issuing, `mail`, the mail's link, the token's lifetime) → a job of a `Passed` start → `sent`, `holds`, `unreachable` or `limited`.

## Invariants
- Run apart from the start's answer, so its work, a key held or a mail sent, is never seen in that answer.
- `settle` first: from the applied state alone it brings the witness's mark and the removals' notices in line, idempotent, so anyone who can start may cause it unharmed. A subject it answers as holding a key, or whose mark is left after it (`heldKeys`), gets nothing, as a first key's reservation reads it.
- The address is the contact users verified last; else the `email` one read by subject answers beside `email_verified` true; else none, and no token is written.
- The mail is sent only once its token is written, so no mail's side comes before its token. Its link carries the token in the fragment, and it expires at the token's end, as issued.
- An identifier is shown masked: its first character, and an address's domain.
