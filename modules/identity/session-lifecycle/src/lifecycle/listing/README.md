# listing

Internal module of `lifecycle`: a subject's listing once a session closes, and the sessions a login's listing pushed out.

## Responsibilities
- Takes a closed session off its subject's listing.
- Keeps for closing, and closes, the sessions a login's listing pushed out over the cap.

## Not here
- Listing a session at login, and the cap (`lifecycle`, over `session-lifecycle`'s listing store).
- Closing a session and its record (`lifecycle`).

## Offers
- `listingOver`: the listing and closings stores, the log, and the lifecycle's close → `unlist` and `closePushedOut`.
- `membersOf` (the listing): the handles listed under a subject, those awaiting their closing included, which a revocation closes.

## Data
- A session is taken off its listing once closed; a failed removal is logged and passed.
- A session pushed out over the cap awaits in the listing, with its end, until it is kept as a closing and settled, so no record is read to keep it. Sessions pushed out are closed by the login that pushed them out, and logged by count only.
- A push-out keeps for closing every session awaiting under the subject, those an earlier push-out left included, before any is closed, so the sweep finishes a close that fails.
- If the closings refuse one, the login is unavailable, the opened session is taken off the listing, and what is still awaiting stays so until the next push-out or a revocation closes it, or its end passes.

## Depends on
- `kernel` (the log); `session-lifecycle`'s store interfaces.
