# sign-up

## Responsibilities
- A person's sign-up (F1): continues a T its start allowed to sign up, through `approvals`' `continueSignUp`. It counts the subjects made, has the ledger make the subject under T's hash, keeps it on T, and has the key management package make its creation.
- Offers the sign-up to `authorize`, and answers it a person with no passkey: every authorization may offer `create()`, so its T allows the sign-up.

## Not here
- When a T allows a sign-up, and T itself: `authorize` and `approvals`. T's continuation, its check and what it keeps: `approvals`.
- `/continue`'s route, its reading and its stages' dispatch; the creation, and the registration that follows: `passkey-management`.
- The subject and its idempotency: `users`' ledger.
- `redirectOnSignUp`: not in 0.1.0 (owner). After a sign-up the RP's `redirect_uri` gets the usual code; the RP treats an unknown `sub` as a new subject and leads the person to its own sign-up (§4.3). Tying it to an account the RP holds is the RP's.

## Offers
- Contributes `continueStages` `sign-up`: the creation as a statement, or a refusal by its reason (`approvals`' words, or `revoked` kept on T); a kept result of neither is a TypeError.
- Contributes `signUpOffers` (`by` `sign-up`) and `withoutPasskey` (`allows`: true, for every client and authorization), and its stance: it holds `newAuthorization`, as a sign-up makes a new subject and its first key and reaches no subject there before, T used by the credential it registered alone (`approvals`).
- Operator section: `per-source`, `per-client` and `total` in `window` (default 3 runs per source, 100 per client and 1000 in all, an hour). `per-client` keeps one client from the total only while below `total`; a deployment of one client may set them alike.

## Invariants
- Composed only by choice (optIn). Composed, an authorization of any client may make a new subject (§4.3). Whether to compose it is the deployment's choice, not a client's.
- Boot is refused where `users`' ledger makes no subjects without an identifier, and, by `authorize`, where another module answers a person with no passkey too.
- Each run of its step is counted before any subject is made, in one window (`rate-limit`'s `rateLimit`): per source, then per T's client, then in all, each only where the one before allows it (a source or client past its own count spends none of the next). Past any it throws Unavailable, making none, and logs `sign-up.limited` with the count (`per-source`, `per-client` or `total`) and, for `per-client`, the client (a signed JAR's word, no person's), never a source.
  - The source is the Front's word: a first, cheap count while the Front is honest, never relied on. What the counts rest on is the client's, its `client_id` from the JAR it signed, which the Front cannot forge, and the total (§4.3).
  - A run again after a passing failure is counted too, in all three: 3 passing failures spend a source's window.
  - What is left (§3.13, Q20): anyone may fill a public client's own window (its sign-ups stop, its logins do not), and enough clients the total. Making a subject makes only the maker's own.
- The subject is made once under T's hash, its idempotency key; the first subject kept on T is the one its creation is for.
- Its refusal for good, `revoked`, is kept on T. A passing failure, or another call holding its step, is thrown, so the screen asks again.
- It writes nothing to the subject's flow: the sign-up's key change is that flow's first record.
- A sealed continuation is no sign-up's (`continuation-wire` seals only `delete` and `rename`): a TypeError.

## Depends on
- `kernel`, `approvals`, `authorize` (`signUpOffers`, `withoutPasskey`), `passkey-management` (`continueStages`, `signUpCreations`), `users`, `rate-limit`, `promises`; `zod`.

## Vocabulary
- sign-up: F1, a person with no passkey making a subject and its first key under a T. T: the authorization's statement.
