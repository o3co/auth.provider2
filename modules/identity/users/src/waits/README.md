# waits

Internal module of `users`: how long a password check of one identifier waits, after that identifier's checks failed in a row.

## Responsibilities
- Holds, per identifier, its failures in a row, and runs each check of it after the wait they set, one check of an identifier at a time.

## Not here
- What a check answers, and the identifier's form: users' own. The section's keys and their bounds: the package.

## Offers
- The rules the package's section `waits` gives: its keys `after`, `first`, `longest` and `forget`, read as `WaitRules`.
- `identifierWaits` (rules, timing, capacity) → `run` (an identifier, a check): the check's answer, after its wait. `WaitRules` (`after`, `firstMs`, `longestMs`, `forgetMs`); `Timing` (a clock, a pause).

## Invariants
- A check answering none adds one failure; a user ends the run; a throw (unavailable among them) leaves it as it was, as no guess was judged.
- The first `after` failures in a row wait for nothing; each further one doubles the next wait from `firstMs`, never past `longestMs`. A run left quiet for `forgetMs` is forgotten.
- Checks of one identifier run in the order asked, each after the one before it ends, so checks sent at once wait in turn; checks of different identifiers never wait for one another.
- An identifier is counted alike whether a user holds it or not, so a wait tells nothing of who exists.
- Held in this process alone: each instance counts its own checks. At most `capacity` identifiers are held (100 000 unless told, a fixed guard); a new one past it lets the oldest idle one go, its run forgotten.

## Vocabulary
- run: an identifier's failed checks in a row, and when the last one failed.
