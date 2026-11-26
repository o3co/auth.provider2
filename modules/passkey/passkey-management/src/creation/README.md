# creation

Internal module of `passkey-management`: a creation statement made (§3.13's registration, step 2).

## Responsibilities
- Makes the creation a subject's evidence binds, and has `approvals` sign it for the screen.

## Not here
- The registration's continuation: the handle a key is attested with, the creation's `user_id` as kept and never one a request sends, and a revocation after the creation, checked again there.
- The statement's signing, record and challenge: `approvals`. Its schema: `sdk-core-wire`. The options' values: `webauthn`. The evidence and the subject it binds: the basis that asks (a first key's path, a passkey-add's approval, a sign-up).

## Offers
- `creationOver` (approvals' `issue`, webauthn's `creation`, `heldKeys`, `passkeyGenerations`, the subject's revocation, random bytes, `account-name`) → a `CreationAsk` (subject, its account masked as `account` or none, basis `first-key` with the ciphertext's hash, or `passkey-add` or `sign-up` with none, evidence, screen, since) → `Issued`, or refused `revoked` or `full`. `creationItems`: the creation's items it fills, every one its schema names.

## Invariants
- A subject revoked since its evidence began gets no creation; nor one holding the most keys passkeys lets it (`full`), so its excluded keys are fewer than that, whatever the basis (a first key's subject holding some is refused `held` where it reserves).
- The statement names the subject's key generation (`passkeyGenerations`; one that moved on since is refused where the key change is decided) and its keys' credentials as excluded, read just before; and of webauthn's own options for a new key, read by their shape (another is a fault), the handle, fresh for each creation, the relying party's id and the algorithms; their challenge apart, which the screen derives from the statement.
- Its issuing is counted by the subject.
- An account with no `account` is named in `user_name` by `account-name`, else the relying party ID of webauthn's options cut to 50 characters, and a short mark of the subject (`nameOf`), within the 64 a `user_name` holds; webauthn's options hold a place for the name, never read.
- A fresh handle for each creation is enough: a key registers to the subject its used approval or token names, never to a handle, and the same person's second credential on one authenticator is refused by the keys excluded.
