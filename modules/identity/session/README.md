# session

## Responsibilities
- Owns the contract of session records: their listing under their subject and their lifecycle (open → closing → closed), as every implementation keeps them; a session is opened only once listed, so a revocation finds every live one.
- Owns the entry decision, and nothing outside an implementation of it decides: a record exists, is open, before its end, and after the subject's revocation boundary.
- A session's end is the end of the delegation it carries, which `open`'s caller fixes as an absolute time; the session keeps it as given, and holds no setting of its length.

## Not here
- Authentication methods, what is issued after a session, and what each amr value means (its giver's vocabulary).
- Keeping sessions: their records, store interfaces, operator section and sweep (`session-lifecycle`, the default implementation).
- A browser's way into a session (a cookie) and the request that carries it: no part of this contract makes or reads one.

## Offers
- `open`: login fact → `opened` with the session and its end at `kernel`'s time, or `revoked`; a login fact `rules`' checks refuse (`checkAuthenticatedAt`, `checkProvenSince`, `checkEndsAt`) is a `TypeError`, before anything is opened; the login is unavailable when the new session cannot be listed under its subject.
  - `provenSince`, when the proof began, is compared with the subject's boundary once the session is saved; revoked, it is closed. A login's authentication time, and what counts from the opening instead, follow `rules`' card.
- `entryOf`: handle → entered (with its end) or absent. `subjectOf`: handle → its record's subject in any state, from one read that writes and judges nothing; none where no record is, or it names none.
- `close`: handle → closed, or pending (the session stays closing) until every participant has finished. It names the moved session (handle and subject) while its record is kept, and the state it found it in (`from`: open, even past its end, closing or closed).
- A revoked subject's listed sessions are each closed through `close`; the revocation answers incomplete while one fails or is left pending (it stays listed). A session pushed out of a full listing (one ending first, never the one being opened) is closed through `close`.
- Extension point `closingParticipants`: the session (its handle and context) → each participant that failed, by name and the error's kind.
  - None is called for a session that ends at its end alone, while a close calls them for a session whose record it finds, even one past its end.
- The seam takes at most one contribution, from the module keeping the participants (`session-participants`); its factory takes `sessions` only late. An implementation refuses to boot where it has no contribution; the stand-in takes none as no participant (`sessionStandIn`).
- `sessionRules`: the rules every implementation keeps alike, the stand-in too (internal module `rules`).
- `./testing`: `stubSessions`; `sessionStandIn`, in memory, as its doc comment says, with `standInListingCap` and `failStandInListing`; `openedOf` (`open`'s session and end, or its throw); `sessionsContract`, the contract tests.

## Invariants
- A session's state only moves forward. A host that cannot read a record (one a newer host wrote, during a rolling upgrade) lets nobody in on it and answers a close of it Unavailable.
- A session's subject is the one its login gave while its record lives, so a caller that kept a handle with its subject never finds them disagree.
- A login's attributes are kept as `login-attributes` keeps them, a frozen copy taken at login, kept unchanged until the session closes.
- A session's end never moves: no setting changed later lengthens or shortens it.

## Depends on
- `kernel`, `login-attributes` (the attributes a login gives), `subject-revocation` (the boundary; the stand-in follows it).

## Vocabulary
- attributes: `login-attributes`' word, under the source that stated them; the source is never read here.
- authentication context: subject, amr, authentication time, and attributes. login fact: the subject, amr, attributes, authentication time, proof's start and end a login hands over. handle: a random value that names one session and can be handed out. participant: a contribution that cleans up when a session closes. end: the time a session ends, the delegation's end.

## Rules for callers
- To end every session of a subject for sure, use revocation: a session ends on its own only at its end.
