# lifecycle

Internal module of `session-lifecycle`: a session's record, and its way from open to closed.

## Responsibilities
- Opens, enters and closes sessions over `session-lifecycle`'s store interfaces.
- Makes the entry decision that `session`'s contract describes.

## Not here
- What `session` offers callers (`session`).
- Taking a session off its listing, and what a login's listing pushed out (`listing`).
- The store interfaces and their needs (`session-lifecycle`'s root).

## Offers
- `lifecycleOver`: the stores, subject revocation, `session`'s seam to the participants, clock, randomness, log, sweep interval and the keeping of attributes → `open`, `close`, `entryOf` and `subjectOf` as `session` describes them, and one sweep: first what a refused push-out left awaiting, then the pending closings, each going on past a failing one.
- The record of a live session: open, before its end, after the subject's revocation boundary, and not pushed out awaiting its closing (one read of the listing).
- A sweep ends at the stop signal, and the host waits for it.
- A close calls the participants through `session`'s `closingParticipants`, and logs each that failed by name and kind.
- A login's authentication time, proof's start and end as `session`'s rules read them (`checkAuthenticatedAt`, `checkProvenSince`, `checkEndsAt`, thrown before a login opens anything; `authenticatedAtOf`).
- A reported time later than the opening is capped to the opening, and only the cap is logged.

## Invariants
- The lifecycle only moves forward: the next state is decided from the state at the time of writing.
- Every state change is written, and a step answers that the state moved only after the confirmed write returns.
- Where a close's update answers nothing (ended, never opened, or its subject erased, its record gone or awaiting its eraser), it answers closed and writes nothing: a handle comes only from a record created before it was listed or handed out, and is never reissued.
- A handle to close is added to the closings first, and taken off once closed.
- A closing whose participants keep failing is retried after half its age (at least the sweep interval, at most 1 hour, a fixed backoff ceiling), and the closing's age is logged (`session-lifecycle.closing_pending`).
- A closing whose record a host cannot read is put off the same way, by that host alone.
- The handle is 256 random bits, and each login gets a new one; a handle already held fails the login.

## Data
- Session record, per handle: format 1, state, the opening time and the end, authentication context (attributes as `session-lifecycle` keeps them), when closing began and when to retry.
- A closed record keeps its subject, its opening and its end; a login's attributes, amr and authentication time are dropped at close.
- Every read checks the record: one of another format or shape lets nobody in, and closing it is unavailable.
- A record lives from login to its end, without end while closing, and for its own length again once closed.
- Each subject's listing: the handle, for what it has left when listed, until its end; a session whose end has passed is not listed, and pushes nothing out.
- A session is listed after its record and before its handle is handed out; a login that cannot list it, or whose save or listing answers `erased` (or the listing `another-subject`), is unavailable, never tried again.
- The listing never pushes out the session being opened.

## Depends on
- `kernel`, `subject-revocation`, `login-attributes` (the form kept attributes are read back in); `session`'s contract and rules; `session-lifecycle`'s store interfaces; `listing`.
