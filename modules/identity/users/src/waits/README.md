# waits

Internal module of `users`: how long a password check of one identifier waits, after that identifier's checks failed.

## Responsibilities
- Holds, per identifier, its failures, and runs each check of it after the wait they set, one check of an identifier at a time, with a bounded queue.

## Not here
- What a check answers, and the identifier's form: users' own. The section's bounds: the package.

## Offers
- The rules the package's section `waits` gives: its keys `after`, `first`, `longest` and `forget`, read as `WaitRules`.
- `identifierWaits` (rules, timing, capacity) → `run` (an identifier, a check): the check's answer, after its wait. `Timing` (a clock, a pause). `queueBound` (4): the checks of one identifier held at once.

## Invariants
- A check answering none adds one failure; a user found and a throw (unavailable among them) leave the failures as they were. Only `forgetMs` with no failure forgets them, so a wait tells nothing of who exists.
- The first `after` failures wait for nothing; each further one doubles the next wait from `firstMs`, never past `longestMs`.
- Checks of one identifier run in the order asked, each after the one before it ends; checks of different identifiers never wait for one another.
- At most `queueBound` checks of one identifier are held, the one under way among them: one more is Unavailable at once, never checked and never counted, a known identifier and an unknown one alike. So a check admitted waits at most `queueBound` × `longestMs` (2 minutes by default) beside the checks' own time, however many were sent before it.
- An identifier is counted alike whether a user holds it or not.
- Held in this process alone: each instance counts its own checks. At most `capacity` identifiers are held (100 000 unless told, a fixed guard). A new one past it lets go an idle one past its forget time, else the idle one with the fewest failures; where every one held has a check under way, it is Unavailable, unchecked.

## Vocabulary
- run: an identifier's failures, and when the last one came.
