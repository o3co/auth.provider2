# first-key

## Responsibilities
- Owns the kinds of a first key's evidence beside the email's token: what a kind's module is given and answers, on one contract every kind sits on.
- Owns a first key's nonces and mail tokens, and the answers of its mail's side: their store interfaces and needs, and its mail's purpose and the values its wording is given.
- Runs a first key's path as the Core's routes: its nonces, its start (§3.13's step 1), its mail's side, which asks `passkey-management`'s `firstKeyCreations` for the creation (step 3, registration's step 2), and a creation's recovery (§C.4). The registration that follows (steps 4 to 6) is `passkey-management`'s `/continue` `register` and `/key/finish`.

## Not here
- A subject's revocation boundary at the start, and a subject holding the most keys: the creation's refusals `revoked` and `full` (`passkey-management`).
- Checking one kind, and its record of who holds it: its own module, declaring its trust and strength to `promises`' `evidenceKinds` under the same name.
- The waits of a password: `users`' `verifyAsPart`, which the password's module asks and hands each start's end.
- Its mail's wording: a template for `mail`'s `mailTemplates`, in a module a deployment replaces (`first-key-mail`).
- A start's answer signed by the Core: `sdk-core-wire`'s code carries none, so a Front can hand a person a false code, which spends the token's tries; no key is bound so.

## Offers
- Extension point `firstKeyEvidence` (keyed by kind): a `FirstKeyEvidence`'s `prepare`, `check` and `settled`, as internal module `evidence` asks them.
- `firstKeyNonces` and `firstKeyTokens`, the stores' interfaces (`Kept`, `StoredNonce`, `StoredToken`), and their needs `firstKeyNoncesNeeds` and `firstKeyTokensNeeds`, as internal modules `nonces` and `tokens` run on them.
- `firstKeyMail`: its mail's purpose, `first-key`, declared to `mail`'s `mailPurposes`, and the values its wording is given: `link`, `account` (the identifier by `passkey-management`'s `masked`), `minutes`.
- Operator section: `mail-link` (https), `token-lifetime` (default 15 minutes), `code-tries` (default 3), `nonce-lifetime` (default 2 minutes), `requests` and `window` (default 30/min per source, each route counted apart), `inbox-only-when-absent` (default off).
- Routes `POST /first-key/nonce`, `/first-key/start`, `/first-key/mail`, `/first-key/recover` (internal modules `routes`, `start`, `mail-side`).
- Metric `auth_first_key_jobs_dropped_total`; lines `first-key.start_ended`, `job_dropped`, `job_failed`, `mail_refused`, `recovery_refused`, naming no address, identifier or subject.
- Declares to `promises`' `evidenceKinds` the inbox, the path's own kind (`evidence`), and its stance on the new authorization's claim: held.
- `./testing`: `firstKeyConfig` (over `FirstKeySettings`), `firstKeyStoreContract` (the stores' contract test), `itemsOf` (each kind's items of a start).
- `FirstKeyStart`: the start's nonce (the path's: short-lived, used up before any check) and the identifier asked for. `EvidenceAnswer`; `StartOutcome`, how the path ended the start: `passed`, `failed` (its own refusals too) or `unavailable` (a kind's fault or its own).

## Invariants
- A kind answers alike, in shape and work, for a subject of none, one holding none of the kind, and one holding it: a subject of none fails. So does `prepare`, alike too for one identifier each time.
- `absent` is the kind's record saying the subject holds none; a record lost fails, and a kind asked of everyone never says it. Each answer stays in the path: the screen is answered alike.
- A kind reads only its own items, under its name in the request's map of kinds, as the screen sent them.
- `prepare` runs before the nonce is used up; `check` once for each kind after, none past the nonce's life; `settled` once for each start a kind checked, after every kind has answered, a fault among them too; one may never come, and a start not told is not passed.
- A start answers alike, in shape and work, whatever its subject, evidence and job: what differs, whether the subject holds a key and gets a mail, runs in one job apart from the answer (internal modules `dispatch`, `issuing`), settling the subject's keys first. A job dropped or lost with its process sends nothing: the person starts again.
- Boot is refused where `users` looks no one up by identifier, no passkey witness is composed, or webauthn takes no ceremony from the mail link's origin.
- The email's token is always asked, being the path's and no kind; where the inbox alone passes, with no kind composed or one answering `absent` to every kind under `inbox-only-when-absent`, the strength's output says so. The rule over the kinds: internal module `evidence`.
- Boot is refused at `first-key` for a kind composed that `promises` holds no declaration of, or holds as past: it would pass unseen by those who rely on the tokens.

## Depends on
- `kernel`, `passkey-management`, `keys`, `users`, `passkeys`, `passkey-witness`, `webauthn`, `mail`, `promises`, `http`, `rate-limit`, `metrics`, `sdk-core-wire`, `front-core-wire`, `front-core-codec`; `zod`

## Vocabulary
- first key: a subject's first passkey, issued through the first key's path to a subject holding none.
- evidence kind: one way the path checks the person beside the email's token.
- start's end: how a start ended over every kind asked, which a kind with waits needs.
