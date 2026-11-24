# session-lifecycle

## Responsibilities
- Keeps sessions for `session`'s contract: their records and listing under their subject, and their lifecycle (open → closing → closed), over its own store interfaces as the assembly wires them.
- Makes the entry decision, opens a new session under a new handle on each login, and keeps a closing session closing until every participant has finished, as `session` describes each.

## Not here
- What callers see of sessions, the rules every implementation keeps, the extension point and the stand-in (`session`).
- Where records are kept (the wiring of its store interfaces).
- A session's end: the login's facts give it, and no setting here lengthens or shortens it.

## Offers
- Provides `session`'s `sessions`, as the adapter that replaces `session` (its default), keeping `sessionRules`.
- Follower of `subject-revocation`, named `session-lifecycle`: closes each listed session of a revoked subject through `close`, by `sessionRules`, and fails when one fails or is left pending (it stays listed), so the revocation answers incomplete.
- The operator section (its keys in the settings list): `sweep-interval`, a time written with its unit (`1m`), a bare number refused; `sessions-per-subject`, how many sessions, each a live authorization, a subject's listing holds (1–10000, default 1000), past which the one ending first is closed. `attributes` holds `login-attributes`' caps (`attributeCaps`), which this section only hosts.
  - With every end set by one delegation length, the one ending first is the oldest; once that length is shortened, a newer authorization may be closed before an older, longer one.
- `sessionsPerSubject`: the section's `sessions-per-subject`, the cap a wiring builds the listing with.
- Each host goes on with pending closes every `sweep-interval`, past a failing one, and with the pushed-out sessions it could not keep for closing; on stop, the host waits for the sweep under way.
- A pushed-out session nobody has kept for closing lets nobody in. One a host forgets by a restart is closed at its subject's next push-out (the login after the next one, once a refused login's session was taken off) or revocation, or ends at its end.
- Logs as `session-lifecycle.*`, never a value: the names a login's attributes dropped (names outside the set as a count), a capped authentication time, a failed participant by name and kind, a closing put off with its age, a sweep's failures and the listing's (a failed removal by kind, sessions pushed out by count).
- Store interfaces of its own, named `session-lifecycle.*`, which a wiring must provide for it: records by handle (create for a subject, read, change from the current contents, with a lifetime or none), the closings (add, done, each) and each subject's listed sessions (add for a lifetime, members, remove, and those pushed out awaiting until settled). The stores never see record contents and need no eviction, crash survival and no rollback on failover.
- Where the Store fences saves past a subject's erasure, a record's create or a listing's add for an erased subject answers `erased`, and a Store keying listings otherwise may answer `another-subject`; a login takes either as refused. A record's change answers nothing.
- The records and the listing read only what a failover keeps, since an entry or a revocation decides on what other requests wrote.
- Its eraser `session-lifecycle` (internal module `erasure`), contributed to `erasure-extensions`' `erasers`: a subject's sessions and listing erased through the stores' optional `erase` and `migrate`, which both stores offer or neither (a part refuses the boot). `logoutGaps` counts the closing, unreadable or live open sessions it removed, in `erasure-extensions`' unit.
- The store interfaces' contracts: `sessionStore`, `closingList`, `subjectSessions`; their needs: `sessionStoreNeeds`, `subjectSessionsNeeds`.
- `./testing`: the configuration builder (`sessionLifecycleConfig`), and contract tests of its store interfaces (`sessionStoreContract`).

## Invariants
- A session is kept for its own length, from its opening to the end its login gave, and listed for what it has left when listed; one whose end has passed takes no place in the listing. A closed one is kept for its length again from its last close.
- `subjectOf` is one read of the record by handle: it ends nothing, and reads the subject of an open, closing or closed one alike; an unreadable record is Unavailable.
- A login naming its authentication time `opening` is taken as authenticated at the opening, known. A login whose time is neither epoch milliseconds (0 to 8.64e15), `opening` nor unknown, or whose proof's start or end is no epoch milliseconds, is a `TypeError`, naming no value, before anything is opened. Its `provenSince` is compared with the subject's revocation boundary once its record is saved: revoked, the session is closed and the login answered `revoked`.
- A login's attributes are kept as `login-attributes` keeps them under the section's `attributes`, a frozen copy taken at login, kept unchanged until the session closes; each read keeps them again, so a cap lowered since drops a value past it.
- It calls the participants through `session`'s `closingParticipants`; boot is refused, naming it, where it has no contribution, never taken as no participant. The seam takes at most one, so `kernel`'s preflight leaves it be: this refusal comes as the sessions are built, in a boot no other gap refused first.
- A host that cannot read a record (one a newer host wrote, during a rolling upgrade) lets nobody in on it and answers a close of it Unavailable.

## Depends on
- `kernel`, `session` (the contract and its rules), `subject-revocation`, `login-attributes` (the attributes a login gives), `erasure-extensions` (the store ports' erasure types).
