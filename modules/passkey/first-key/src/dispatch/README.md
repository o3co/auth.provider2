# dispatch

Internal module of `first-key`: jobs run apart from the answers that put them.

## Responsibilities
- Runs each job it is put apart from the put, up to a bound under way, between start and stop, and waits for those under way at stop.

## Not here
- What a job does: internal module `issuing`. Writing down a job dropped or failed: the package, from what it is told.

## Offers
- `dispatchOver` (the bound, `Told`: `dropped`, `failed`) → `put` (a job), `start`, `stop` (a signal).

## Invariants
- A put never waits and never throws: past the bound under way, before start or after stop, the job is dropped, told, and never run, so whoever puts it answers alike either way.
- A job runs deferred, after its put returns; one that throws, at once or later, is told as failed.
- At stop no job is taken; those under way are waited for until the signal aborts, then let be.
- Held in this process alone: a job not run before the process ends is never run.
- Its package's hooks come before `http`'s: it is started before any route is served, and stopped after `http` has drained, so the jobs the last requests put are waited for.
