# passkeys

## Responsibilities
- Keeps passkeys: a subject's keys, as its flow's state holds them, the one reservation of a key being registered, and each credential's record (its binding to a subject, its count, and what its authenticator answered beside the key).
- Owns the reservation's states and the key change's records and end, which its writer registers; answers assertions by active keys through `webauthn`'s ceremonies.

## Not here
- The ceremonies and the relying party: `webauthn`. Challenges, their lifetimes and use-once marks: the caller's, kept with its request.
- The key change's preimage, its `bundle` and `resend`, sending it and taking it in: its writer's and `transparency`'s. The fold: `authority-rules`.
- A reset, emptying a subject's keys: the embedder's signed instruction, put on the log as the boundary record (A11) and taken in through the keys' owner, the fold moving the key generation on (`passkey-reset`).
- Who may register a key, on what grounds, and for which subject: the caller's, standing on the promises. Keeping the witness's mark: the module contributing `passkeyWitnessing`.
- A subject's active credentials listed, their labels and creation times, and renaming: the key management package and `passkey-manage` add them.

## Offers
- `passkeys`, which any module may take: `assert` (a response, its request's challenge and the credentials it named, `allow`) → subject, credential, user verified, backup eligible; or a refusal. `publicKeyOf` (credential) → an active key's subject and public key. `settle` (subject) → whether it holds a key.
- `registrations`, taken only by a module standing on the promises (`promises`' `stances`): `reserve` (the key generation its approval names; `first`: only where the subject holds no key; `retrying` one), `verifyPending`, `commit` (KE-C01, its op the reservation), `cancel`, `remove` (KE-C01 of a removal).
- `passkeyChanges`: the key change's kind (name, part, records, end) its writer registers on `operationKinds`, with its `bundle` and `resend`, and records of its own after passkeys'. `passkeysGone` (state, credential): the credentials a removal takes. `passkeyPart`: the part, which its wiring binds.
- Extension points `passkeyWitnessing` (at most one: `marked`, `mark` and `withdraw`, by key generation) and `passkeyRemovals` (any number: `removed`, told at least once).
- `passkeyStore`, the credential records' store interface (create unless held, read, change from what it holds), and `passkeyStoreNeeds`.
- Operator section: `user-verification` (default `required`; any other breaks the promise of a new login, `front-compromise-new-authorization`), `pending-lifetime` (default 10 minutes), `max-credentials` (default 10).
- `./testing`: `passkeysConfig` (`PasskeysSettings`), and `passkeyStoreContract`, the store interface's contract test.

## Invariants
- A key is usable only once active: reserved, its possession shown by an assertion over a request naming it alone (`verifyPending`, answering the response that verified it alike again), its key change committed and taken in with `took`. Reads are of the applied state: a removal on the log but not taken in still reads active.
- The reservation holds its version (its key change's op), state, key, key generation and lapse; being put on the log is shown by the frame alone. Reserved → verified → active (end `took`); a verified one ends `held` or `abandoned` as ended, and stays verified on any other end. Reserved, verified and ended ones are cancelled, or replaced by a retry (keeping their key generation) or once lapsed.
- `reserve`, `verifyPending`, `cancel` and `settle` change passkeys' records only through `transparency`'s `changeHeld`, held to what they read: never while an op is open on the flow (`open`), never in the store directly.
- `commit` decides only on a verified reservation, by its verification, before it lapses, under the key generation it was reserved under, while the subject holds fewer than `max-credentials` keys, none for a `first` one; the writer's changes must register its key. The writer's own records of the kind are written as it gives them.
- `remove` refuses, in the write deciding it, a removal after which the subject holds no key, counting each key whose chain holds the removed one (`authority-rules`' `withoutRooted`), and the reservation's op: no op of passkeys empties a subject's keys.
- `settle` is run by whoever took in an end of a key change: its writer, or a replica whose tending ended one. From the applied state alone, idempotent: tells `passkeyRemovals` of each credential gone since the last settle, sets the mark while a key is held, and withdraws a mark only once the key generation moved past its own, never for state found missing. Until it runs after a `took`, a new key carries no mark.
- `assert` takes only a credential its request named, where it named any (WebAuthn §7.2), and moves the count on only over the record judged (`raced` otherwise).
- A credential's record binds one subject: `reserve` refuses another's, never lowers the count nor rewrites the details kept, and a reservation cancelled or replaced releases a binding never active. A store that cannot tell is unavailable, never a refusal.
- A passkey witness composed with no witnessing, or two witnessings, refuse boot; so does `registrations` where no writer registers the key change's kind.

## Data
- Its part of each subject's flow, in the frames' store: the keys record, the reservation and what the last settle told of; an erasure boundary empties the keys.
- Credential records by credential id, kept without end through the passkey store. After a subject's erasure, the binding to its subject and the count remain, as the log keeps the key on the subject's flow; the details (handle, transports, backup state) go at the settle that finds the key gone.

## Depends on
- `kernel`, `promises` (the stances its takers declare), `transparency` and `transparency-wire` (the frame, the kinds, the owners, flows), `authority-rules` (the state's schema, `withoutRooted`), `webauthn` (the ceremonies, the credential's form), `passkey-witness` (whether a witness is composed).

## Vocabulary
- key: a credential the subject's flow state holds active. reservation: a key's registration in progress, one per subject. version: a reservation's op id; a retry makes a new one. binding: a credential record's subject.
