# rules

Internal module of `session`: the rules every implementation of `sessions` keeps alike, the stand-in too, offered as `sessionRules`.

## Responsibilities
- Closes a subject's listed sessions in their one order, and reads a login's authentication time, proof's start and end.

## Not here
- When each is called, and what is logged of a failure (the implementation, or the stand-in).

## Offers
- `closeListed`: closes each listed session of a subject through the close given, one at a time in the listing's order, past one that fails or is left pending, and then fails.
- `checkAuthenticatedAt`: a `TypeError`, naming no value, for a login's authentication time neither epoch milliseconds (0 to 8.64e15), `opening` nor `unknown`. `checkProvenSince`: a `TypeError`, naming no value, for a proof's start missing or not epoch milliseconds; `checkEndsAt`, the same for an end missing or not whole epoch milliseconds.
- `authenticatedAtOf` (the login's facts, the opening, what to do where it caps a later time) → the time the session keeps.

## Invariants
- A login's authentication time is kept: the opening for a login the provider authenticates itself (`opening`); an upstream's login keeps the time the upstream reports, the opening time when it gives a later one; one it reports unknown is answered as `authenticatedAtUnknown` and never counts as fresh. The subject's revocation boundary counts from the opening instead.

## Depends on
- `kernel` (Unavailable); `session`'s contract.
