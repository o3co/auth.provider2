# passkey-management

## Responsibilities
- Makes a key's creation for a subject on its basis (§3.13's registration, step 2): a first key's, a passkey-add's, a sign-up's (F1); and registers it (steps 4 to 6), writing its key change.
- Runs a passkey-add (§3.13's step 1): its approval by a live key, the creation it bases, then the shared registration; and a passkey-manage: its approval's list of keys, a rename or a delete by `/continue`. As the Core's routes.

## Not here
- A subject's revocation boundary at the start: its creation is refused once one followed the evidence (internal module `creation`).
- The first key's path, its evidence, nonces, mail tokens and mail: `first-key`, which asks `firstKeyCreations` for its creation.

## Offers
- Extension point `continueStages`: a stage of `/continue` (its word as `continuation-wire` names it) and how it goes on, one module each; `register`, `rename`, `delete` its own.
- `signUpCreations`: a sign-up's creation (F1), for the `sign-up` package (internal module `keying`).
- `firstKeyCreations`, taken by `first-key` alone: a first key's creation (`FirstKeyCreationAsk`: the subject, the identifier, the sealed request's digest, the evidence, the screen, since) → `FirstKeyCreated`, issued or refused `revoked` or `full`; approvals' other refusals told by `creation_refused`'s reason, then thrown (internal module `keying`). `masked`: how an identifier shows, in a creation's `account` and in a first key's mail.
- `keyChangePart`: its part of a subject's flow, a key change's preimage kept for a resend (or an expired op's mark), bound by a store; `keyChangePartNeeds`, what that store's place must be.
- Operator section: `requests` and `window` (default 30/min per source, each route counted apart), `account-name` (default the relying party ID).
- Routes `POST /continue`, `/key/finish`, `/approval/start` and `/approval/finish` (internal modules `routes`, `registration`, `approval`, `keying`).
- Lines `passkey-management.continue_refused`, `approval_refused`, `registration_refused`, `creation_refused`, naming no address, identifier or subject.
- `./testing`: `passkeyManagementConfig` (over `PasskeyManagementSettings`).

## Invariants
- Where no identifier is asked, a creation's `account` is the address its subject verified last, masked (`masked`); with none, its `user_name` is `account-name`, else the relying party ID cut to 50 characters, and a short mark of the subject, as F1's is (`nameOf`). Where identifiers are no addresses, a first key and a later one may show apart.
- It writes a key added's change, a first key's, a passkey-add's or a sign-up's, as the kind's writer, and completes it only with a receipt (internal modules `registration`, `key-change`).
- A key a passkey-add approves breaks none of the new authorization's claim (P1): its stance holds it.

## Depends on
- `kernel`, `users`, `passkeys`, `approvals`, `webauthn`, `subject-revocation`, `promises`, `http`, `rate-limit`, `transparency`, `transparency-wire`, `sdk-core-wire`, `front-core-wire`, `continuation-wire`; `zod`

## Vocabulary
- first key: a subject's first passkey, issued through the first key's path to a subject holding none; here, a creation's basis.
