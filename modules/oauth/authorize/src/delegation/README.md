# delegation

Internal module of `authorize`: how long a login's delegation lasts, which its session ends by.

## Responsibilities
- Reads the delegation's length from `refresh`, the one setting of it (O27), for the finish to end a session it opens.

## Not here
- Opening the session (`finish`). The length itself, and a family's end by it (`refresh`).

## Offers
- `delegationSecondsIn` (the composition) → the length, in seconds; `delegationTakes`.

## Invariants
- A session ends at its statement's issue and this length, the same end as the refresh family founded with it.

## Depends on
- `refresh` (`delegation`), `kernel`.
