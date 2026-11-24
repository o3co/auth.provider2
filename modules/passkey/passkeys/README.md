# passkeys

## Responsibilities
- Keeps passkeys: a subject's keys, as its flow's state holds them, the one reservation of a key being registered, and each credential's record (its subject and what its authenticator answers beside the key).
- Owns the reservation's states and the key change's records and end, which its writer registers; answers assertions by active keys through `webauthn`'s ceremonies.

## Not here
- The ceremonies and the relying party: `webauthn`. Challenges, their lifetimes and use-once marks: the caller's, kept with its request.
- The key change's preimage, its `bundle` and `resend`, sending it and taking it in: its writer's and `transparency`'s. The fold: `authority-rules`.
- Who may register a key, on what grounds, and for which subject: the caller's, standing on the promises. The witness's mark: the module contributing `passkeyWitnessing`.

## Offers
- `passkeys`, which any module may take: `assert` (a response, its request's challenge and the credentials it named, `allow`) → subject, credential, user verified, backup eligible; or a refusal. `publicKeyOf` (credential) → an active key's subject and public key. `settle` (subject, the credentials a key change took off) → whether it holds a key.
- `registrations`, taken only by a module standing on the promises (`promises`' `stances`): `reserve` (`first`: only where the subject holds none; `retrying` a reservation), `verifyPending`, `commit` (KE-C01, its op the reservation), `cancel`, `remove` (KE-C01 of a removal; never the last key, `last`).
- `passkeyClearing`, taken as `registrations` is: `clear`, a removal that may take the last key.
- `passkeyChanges`: the key change's kind of operation (name, part, records, end) its writer registers on `operationKinds`, with its `bundle` and `resend`. `passkeyPart`: the part its records are in, which its wiring binds.
- Extension points `passkeyWitnessing` (at most one: `settle`) and `passkeyRemovals` (any number: `removed`, told by `settle`).
- `passkeyStore`, the credential records' store interface (create unless held, read, change from what it holds), and `passkeyStoreNeeds`.
- Operator section: `user-verification` (default `required`; any other breaks the promise of a new login, `front-compromise-new-authorization`), `pending-lifetime` (default 10 minutes), `max-credentials` (default 10).
- `./testing`: `passkeysConfig` (`PasskeysSettings`), and `passkeyStoreContract`, the store interface's contract test.

## Invariants
- A key is usable only once active: reserved, its possession shown by an assertion over a request naming it alone (`verifyPending`), its key change committed and taken in with `took`. A pending key asserts nothing and has no public key.
- The reservation holds its version (its key change's op), state, key, key generation and lapse. Being put on the log is shown by the frame alone: it holds no such mark of its own.
- Its states: reserved → verified (`verifyPending`) → active (end `took`); a verified one ends `held` or `abandoned` as ended, and stays verified on any other end. Reserved, verified and ended ones are cancelled, or replaced by a retry, which keeps their key generation.
- `reserve`, `verifyPending` and `cancel` change it only through `transparency`'s `changeHeld`, held to what they read: never while an op is open on the flow (`open`), never in the store directly. A lapsed one holds no pending place.
- `commit` decides only on a verified reservation, by its verification, before it lapses, under the key generation it was reserved under, while the subject holds fewer than `max-credentials` keys, none for a `first` one; the writer's changes must register its key.
- The subject's last key is taken off by `passkeyClearing` alone: `remove` refuses it in the write that decides the removal.
- `assert` takes only a credential its request named, where it named any (WebAuthn §7.2), and moves the count on only over the record judged (`raced` otherwise). `reserve` refuses a credential another subject's record names.
- A passkey witness composed with no witnessing, or two witnessings, refuse boot; so does `registrations` where no writer registers the key change's kind.

## Data
- Its part of each subject's flow, in the frames' store: the keys record (the key generation, the keys) and the reservation.
- Credential records by credential id, kept without end, through the passkey store.

## Depends on
- `kernel`, `promises` (the stances its takers declare), `transparency` and `transparency-wire` (the frame, the kinds, the owners, flows), `authority-rules` (the state's schema), `webauthn` (the ceremonies, the credential's form), `passkey-witness` (whether a witness is composed).

## Vocabulary
- key: a credential the subject's flow state holds active. reservation: a key's registration in progress, one per subject. version: a reservation's op id; a retry makes a new one.
