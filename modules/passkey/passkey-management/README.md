# passkey-management

## Responsibilities
- Owns the kinds of a first key's evidence beside the email's token: what a kind's module is given and answers, on one contract every kind sits on.
- Owns a first key's nonces and mail tokens, and the answers of its mail's side: their store interfaces and needs, and its mail's purpose and the values its wording is given.
- Runs a first key's path: its nonces, its start (§3.13's step 1), its mail's side and its creation (step 3, registration's step 2), and a creation's recovery (§C.4), as the Core's routes.
- Runs a passkey-add (§3.13's step 1): its approval by a live key, the creation it bases, then the shared registration (steps 4 to 6); and a passkey-manage: its approval's list of keys, a rename or a delete by `/continue`. As the Core's routes.

## Not here
- A subject's revocation boundary at the start: its creation is refused once one followed the evidence (internal module `creation`).
- Checking one kind, and its record of who holds it: its own module, declaring its trust and strength to `promises`' `evidenceKinds` under the same name.
- The waits of a password: `users`' `verifyAsPart`, which the password's module asks and hands each start's end.
- Its mail's wording: a template for `mail`'s `mailTemplates`, in a module a deployment replaces (`passkey-management-mail`).
- A start's answer signed by the Core: `sdk-core-wire`'s code carries none, so a Front can hand a person a false code, which spends the token's tries; no key is bound so.

## Offers
- Extension point `firstKeyEvidence` (keyed by kind): a `FirstKeyEvidence`'s `prepare`, `check` and `settled`, as internal module `evidence` asks them.
- Extension point `continueStages`: a stage of `/continue` (its word as `continuation-wire` names it) and how it goes on, one module each; `register`, `rename`, `delete` its own.
- `firstKeyNonces` and `firstKeyTokens`, the stores' interfaces, and their needs `firstKeyNoncesNeeds` and `firstKeyTokensNeeds`, as internal modules `nonces` and `tokens` run on them.
- `firstKeyMail`: its mail's purpose, `first-key`, declared to `mail`'s `mailPurposes`, and the values its wording is given: `link`, `account`, `minutes`.
- `signUpCreations`: a sign-up's creation (F1), for the `sign-up` package (internal module `keying`).
- `keyChangePart`: its part of a subject's flow, a key change's preimage kept for a resend, bound by a store.
- Operator section: `mail-link` (https), `token-lifetime` (default 15 minutes), `code-tries` (default 3), `nonce-lifetime` (default 2 minutes), `requests` and `window` (default 30/min per source), `inbox-only-when-absent` (default off), `account-name` (default the mail link's host).
- Routes `POST /first-key/nonce`, `/first-key/start`, `/first-key/mail`, `/first-key/recover` (internal modules `routes`, `start`, `mail-side`), `/continue`, `/key/finish`, `/approval/start` and `/approval/finish` (`registration`, `approval`, `keying`).
- Metric `auth_first_key_jobs_dropped_total`; lines `passkey-management.start_ended`, `job_dropped`, `job_failed`, `mail_refused`, `recovery_refused`, `continue_refused`, `approval_refused`, `registration_refused`, naming no address, identifier or subject.
- Declares to `promises`' `evidenceKinds` the inbox, the path's own kind (`evidence`).
- `./testing`: `passkeyManagementConfig`, `firstKeyStoreContract` (the stores' contract test), `itemsOf` (each kind's items of a start).
- `FirstKeyStart`: the start's nonce (the path's: short-lived, used up before any check) and the identifier asked for. `EvidenceAnswer`; `StartOutcome`, how the path ended the start: `passed`, `failed` (its own refusals too) or `unavailable` (a kind's fault or its own).

## Invariants
- Where no identifier is asked, a creation's `account` is the address its subject verified last, masked as a first key's mail shows its identifier; with none, its `user_name` is `account-name` and a short mark of the subject, as F1's is (`accountOf`, `nameOf`). Where identifiers are not addresses, a subject's first key and a later one may show apart.
- A kind answers alike, in shape and work, for a subject of none, one holding none of the kind, and one holding it: a subject of none fails. So does `prepare`, alike too for one identifier each time.
- `absent` is the kind's record saying the subject holds none; a record lost fails, and a kind asked of everyone never says it. Each answer stays in the path: the screen is answered alike.
- A kind reads only its own items, under its name in the request's map of kinds, as the screen sent them.
- `prepare` runs before the nonce is used up; `check` once for each kind after, none past the nonce's life; `settled` once for each start a kind checked, after every kind has answered, a fault among them too; one may never come, and a start not told is not passed.
- A start answers alike, in shape and work, whatever its subject, evidence and job: what differs, whether the subject holds a key and gets a mail, runs in one job apart from the answer (internal modules `dispatch`, `issuing`), which settles the subject's keys first. A job dropped or lost with its process sends nothing: the person starts again.
- Boot is refused where `users` looks no one up by identifier, no passkey witness is composed, or webauthn takes no ceremony from the mail link's origin.
- It writes a key added's change, a first key's or a passkey-add's, as the kind's writer, and completes it only with a receipt (internal modules `registration`, `key-change`).
- The email's token is always asked, being the path's and no kind; where the inbox alone passes, with no kind composed or one answering `absent` to every kind under `inbox-only-when-absent`, the strength's output says so. The rule over the kinds composed: internal module `evidence`.
- Boot is refused at `passkey-management` for a kind composed that `promises` holds no declaration of, or holds as past: it would pass unseen by those who rely on the tokens.

## Depends on
- `kernel`, `keys`, `users`, `passkeys`, `passkey-witness`, `approvals`, `webauthn`, `subject-revocation`, `mail`, `promises`, `http`, `rate-limit`, `metrics`, `transparency`, `transparency-wire`, `sdk-core-wire`, `front-core-wire`; `zod`

## Vocabulary
- first key: a subject's first passkey, issued through the first key's path to a subject holding none.
- evidence kind: one way the path checks the person beside the email's token.
- start's end: how a start ended over every kind asked, which a kind with waits needs.
