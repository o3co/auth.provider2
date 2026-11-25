# mail-side

Internal module of `passkey-management`: a first key's mail's side, and a creation's recovery.

## Responsibilities
- Takes the mail's side's sealed request to the creation it is answered with, kept for it; and answers a recovery that request's E_sig signed.

## Not here
- The nonce, the token and its answer, the sealing, the creation: internal modules `nonces`, `tokens`, `sealed`, `creation`.

## Offers
- `mailSideOver` (the keys' opening, the nonces, users' lookup by identifier, the tokens, the creation) → `mail` (a `SealedRequest`) → `answered` (the statement), `refused` (with why: `nonce`, `unopened`, `token`, `revoked`, `full`, `answer`, `recovery`), `unavailable` (a statement's own refusal, its word) or `withdrawn`; `recover` (`Recovery`: the mail's nonce, its request's digest, E_sig's signature) → the same.

## Invariants
- In this order (its D4's §7.5 to §7.8): the nonce bound to the request, the same request again going on and any other refused; the request opened; the identifier looked up; the token tried in one write with that subject and the code.
- An answer kept is read before any creation: a request taken up after a fall gets it, never another. A creation is made only for a token claimed by this request, kept once for its nonce, and given only while the token is used by this request.
- The creation names the token's own subject, never the one the identifier names now (that one is only tried against it), the masked identifier, the token's hash as its evidence, the request's digest as its ciphertext hash, and when the token's evidence began, the start's time.
- A subject revoked since, or holding the most keys it may (`full`), is refused; a statement's own refusal (busy, limited, items, withdrawn) is `unavailable`, its word kept for the log.
- A recovery is answered only where the answer kept names its digest and E_sig signed `firstKey.recoverInput` of the nonce and digest, while its token is used by that request; it makes nothing.
- Every refusal is one to the screen: the routes answer `access_denied`; why is for the log alone, naming no subject or identifier.
