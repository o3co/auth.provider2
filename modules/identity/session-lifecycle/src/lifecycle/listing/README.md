# listing

Internal module of `lifecycle`: a subject's listing once a session closes, and the sessions a login's listing pushed out.

## Responsibilities
- Takes a closed session off its subject's listing, and off those awaiting.
- Keeps for closing, and closes, the sessions a login's listing pushed out over the cap.

## Not here
- Listing a session at login, and the cap (`lifecycle`, over `session-lifecycle`'s listing store).
- Closing a session and its record (`lifecycle`).

## Offers
- `listingOver`: the listing and closings stores, the log, and the lifecycle's close → `unlist`, `closePushedOut`, `awaits` (whether a handle awaits its closing) and `retryAwaiting` (one sweep's turn).
- `membersOf` (the listing): the handles listed under a subject, those awaiting their closing included, which a revocation closes.

## Data
- A session is taken off its listing and settled once closed; a failed write is logged by its step and passed.
- A session pushed out over the cap awaits in the listing, with its end, until a close of it finishes and settles it, so no record is read to keep it and nobody enters it meanwhile. Sessions pushed out are closed by the login that pushed them out, and logged by count only.
- A push-out keeps for closing every session awaiting under the subject, those an earlier push-out left included, before any is closed, so the sweep finishes a close that fails.
- If the closings refuse one, the login is unavailable, the opened session is taken off the listing, and the subject is remembered on this host: each sweep keeps what still awaits for closing and closes it, until the closings take it all. What awaits is also closed at the next push-out or by a revocation, or ends at its end; this host's memory is lost on a restart.

## Depends on
- `kernel` (the log); `session-lifecycle`'s store interfaces.
