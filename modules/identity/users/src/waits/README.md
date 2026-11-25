# waits

Internal module of `users`: how long a password check of one identifier waits, after that identifier's checks failed.

## Responsibilities
- Holds, per identifier, its failures, and runs each check of it after the wait they set, one check of an identifier at a time, with a bounded queue.

## Not here
- What a check answers, and the identifier's form: users' own. The section's bounds: the package.

## Offers
- The rules the package's section `waits` gives: its keys `after`, `first`, `longest` and `forget`, read as `WaitRules`, and `capacity`.
- `identifierWaits` (rules, timing, capacity, full: told of each identifier a full table refuses) → `run` (an identifier, a check): the check's answer, after its wait; `runPending`: the answer `Pending`, a user found counted a failure until `settle(true)`. `Timing` (a clock, a pause). `queueBound` (4): the checks of one identifier held at once. `fullTelling`: counts each refusal and writes at most once in a given time.
- `failedChecksWithin` (rules): the most failed checks of one identifier in any window of `forgetMs`: one run's, its first wait maybe before the window, and one more for a run forgotten at its edge.

## Invariants
- A check answering none adds one failure; a user found and a throw (unavailable among them) leave the failures as they were. Only `forgetMs` with no failure forgets them, so a wait tells nothing of who exists.
- A pending check adds one either way, and counts its time towards forgetting; settled once, it takes back a user found's where passed, unless the run was forgotten since. A whole that failed for a fault is not passed: a fault elsewhere never lets a check go uncounted, and an owner's checks build failures while it lasts.
- The first `after` failures wait for nothing; each further one doubles the next wait from `firstMs`, never past `longestMs`.
- Checks of one identifier run in the order asked, each after the one before it ends; checks of different identifiers never wait for one another.
- At most `queueBound` checks of one identifier are held, the one under way among them: one more is Unavailable at once, never checked and never counted, a known identifier and an unknown one alike. So a check admitted waits at most `queueBound` × `longestMs` (2 minutes by default) beside the checks' own time, however many were sent before it.
- While a sender keeps an identifier's queue full, its owner's checks are answered Unavailable: the per-identifier wait's own limit. While one keeps a failure on each of `capacity` identifiers within `forgetMs`, every identifier not held is: the table's, so the failed checks stated hold. Limiting each sender is the layer in front's.
- An identifier is counted alike whether a user holds it or not.
- Held in this process alone: each instance counts its own checks. At most `capacity` identifiers are held (the section's, 100 000 by default, 1 000 to 1 000 000; about 0.5 KB each at the longest identifier, so 50 MB by default). A new one past it lets go an idle one past its forget time; where none is, it is Unavailable, unchecked, so no failure not forgotten is let go and `failedChecksWithin` holds. A restart forgets them all.

## Vocabulary
- run: an identifier's failures, and when the last one came.
