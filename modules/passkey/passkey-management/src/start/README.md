# start

Internal module of `passkey-management`: a first key's start (§3.13's step 1).

## Responsibilities
- Uses a start's nonce, opens its request, looks its subject up, asks its evidence, and answers its code sealed to the screen; puts one job for every start.

## Not here
- What the job does: internal module `issuing`. The nonce, the sealing, the evidence's rule, the jobs' running: `nonces`, `sealed`, `evidence`, `dispatch`.

## Offers
- `startOver` (the keys' opening and sealing, the nonces, users' lookup by identifier, the evidence, the dispatch, the job, random bytes, what to write down of a job's end) → a start (`SealedRequest`) → `answered` (the code sealed), `refused` or `withdrawn`. `Ended`.

## Invariants
- The nonce is used before the request is opened, and once: a nonce used again is `refused`, so a start is never taken up again; a lost answer is a new start.
- Opened, every start does the same: looks its identifier up, asks every kind of evidence, draws a code, seals it, then puts one job; where the code cannot be sealed, the job only tells the start's end, unavailable, and the fault is thrown. The code is sealed to the screen's `eEnc` under `hpke.info.firstKeyCode` and the start's additional data. Its answer is alike whatever the subject, the evidence or the job.
- The job runs issuing only for a subject the identifier names and evidence that passed, then tells every kind the start's end: passed only where its mail went out; unavailable where a kind or the job's own work faulted; else failed, a mail its limits refused among them.
- What a job's end writes down names no address, identifier or subject.
