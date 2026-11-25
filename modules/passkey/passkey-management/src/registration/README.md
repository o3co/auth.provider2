# registration

Internal module of `passkey-management`: a first key's registration after its creation (§3.13's registration, steps 4 to 6).

## Responsibilities
- Takes the creation's `register` continuation: attests the new key, reserves it and has `approvals` sign its possession. Finishes from the possession and the new key's assertion: verifies the pending key, uses the possession, puts the key change on the subject's flow and has `approvals` complete it.

## Not here
- The continuation's signature, sequence and kept answer, the statements and completions: `approvals`. The reservation, its verification and the keys: `passkeys`. The change on the flow and its receipt: internal module `key-change`.
- A creation of another basis (`passkey-add`, `sign-up`): refused here. Deleting and renaming a key: passkey-manage.
- `sdk-core-wire`'s keyChange `receipt?` is for a bundle that pins no log key (L0), never for a change another replica took in first: that one is completed with the log's first receipt, asked again.

## Offers
- `registrationOver` (`RegistrationParts`) → `register` (a `Continuation`: the creation, its sequence number, the `create()` response's JSON text, E_sig's signature) → the possession, and `finish` (the possession, the assertion's JSON text as sent) → the completion sealed to the screen; or refused, with a reason for the log alone. `possessionItems`: the possession's items it fills.

## Invariants
- A step that throws (the possession's issuing counted out, busy or withdrawn, the flow open) keeps nothing: `approvals` holds its sequence number 30 seconds, then the same continuation runs it again.
- The step reads the creation from its record (`KeptCreation`); the response is attested over the creation's `create` challenge with the user verified, its handle the creation's `user_id`, never one a request sends. A credential id past 1023 bytes, or a key of an algorithm the creation did not offer, is refused, so no key is listed that a continuation cannot name. A subject revoked since the creation was issued is refused, at the step and at the finish.
- A pending reservation of the same credential and key is carried on as it is, never replaced, so a step run again (its first call fell after it reserved, or ran late past another's) names the reservation a kept possession may name. The credential and key name the reservation; the possession names the creation its step ran under, and only the key's holder finishes it, by an assertion over that possession. Any other pending reservation refuses (`pending`).
- At the finish, the possession's `creation_hash` and the subject it leads to are only what the verification is checked against until `use` holds the possession used: from then on they are the Core's. The pending key's user must be verified (`userVerified`), whatever `passkeys`' section says. Its public key is the pending reservation's, which must be the possession's, its thumbprint the possession's `key_jkt`.
- A completion kept is answered first, whatever lapsed since. A completion is signed only with a receipt (none given, or the ring signing no more, is unavailable): the change's own, or the log's first, asked again (`receipts`) for a change already placed. Nothing is completed for a change not placed.

## Depends on
- `approvals`, `passkeys` (`registrations`, `heldKeys`, `publicKeyOf`), `webauthn`, `subject-revocation`, `sdk-core-wire`, `kernel`; internal module `key-change`.
