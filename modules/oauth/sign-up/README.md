# sign-up

## Responsibilities
- A person's sign-up (F1): continues a T its start allowed to sign up, through `approvals`' `continueSignUp`. It counts the subjects made, has the ledger make the subject under T's hash, keeps it on T, and has the key management package make its creation.
- Offers the sign-up to `authorize`, so a T whose screen may offer `create()` allows it.

## Not here
- When a T allows a sign-up, and T itself: `authorize` and `approvals`. T's continuation, its check and what it keeps: `approvals`.
- `/continue`'s route, its reading and its stages' dispatch; the creation, and the registration that follows: `passkey-management`.
- The subject and its idempotency: `users`' ledger.

## Offers
- Contributes `continueStages` `sign-up`: the creation as a statement, or a refusal by its reason (`approvals`' words, or `revoked` kept on T); a kept result of neither is a TypeError.
- Contributes `signUpOffers` (`by` `sign-up`), and its stance: it holds `newAuthorization`, as a sign-up makes a new subject and its first key and reaches no subject there before, T used by the credential it registered alone (`approvals`).
- Operator section: `per-source` and `total` in `window` (default 3 runs per source and 1000 in all, an hour).

## Invariants
- Composed only by choice (optIn). Boot is refused where `users`' ledger makes no subjects without an identifier.
- Each run of its step is counted, per source first and then, only where its source's count allows it, from every source, in one window (`rate-limit`'s `rateLimit`), before any subject is made; past either it throws Unavailable, making none, and logs `sign-up.limited` with the count (`per-source` or `total`), no source. A run again after a passing failure is counted too, so 3 passing failures spend a source's window.
- The subject is made once under T's hash, its idempotency key; the first subject kept on T is the one its creation is for.
- Its refusal for good, `revoked`, is kept on T. A passing failure, or another call holding its step, is thrown, so the screen asks again.
- It writes nothing to the subject's flow: the sign-up's key change is that flow's first record.
- A sealed continuation is no sign-up's (`continuation-wire` seals only `delete` and `rename`): a TypeError.

## Depends on
- `kernel`, `approvals`, `authorize` (`signUpOffers`), `passkey-management` (`continueStages`, `signUpCreations`), `users`, `rate-limit`, `promises`; `zod`.

## Vocabulary
- sign-up: F1, a person with no passkey making a subject and its first key under a T. T: the authorization's statement.
