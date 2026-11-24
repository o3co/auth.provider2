# users

## Responsibilities
- Owns who a user is and how they are known to be the same person: verification and verified contacts.
- Answers from the settings' users or one contributed user ledger, and keeps verified contacts through its Store interface.

## Not here
- Steps after verification, how much of the attributes to expose, registration, password reset, when to verify a contact, and the proofs each feature keeps.

## Offers
- `verify` (identifier, password), `bySubject` and `byIdentifier`, each answering a user or none; `bySubject` and `claimedContacts` may answer unanswerable. `create` (identifier): a new subject the ledger makes, or `exists`; offered only where the composed ledger makes subjects, its absence the composition's fact.
- `claimedContacts`, `verifiedContact` (subject, `{ kind: "email", value }`) and `contactsOf`.
- Extension point `ledgers`: a user ledger (verification, user by subject or unanswerable, by identifier, and optionally a create and an import, `keep`), which takes the same work for an unknown identifier as for a known one.
- Operator section `registered`: `identifier`, `subject` (default the identifier), `password-hash`, `attributes`.
- Operator section `waits`: how a password check of an identifier that failed waits; its keys: internal module `waits`.
- Store interface for verified contacts; what it needs, its erasure ports, and the eraser `users`: internal module `stores`.
- `userAttribute`, typed by `UserAttributes`: the attributes users names, by OIDC claim name `email`, `email_verified`, `name`, `picture` and `groups`; a user may hold others. `isAttributeValue` (name, value): whether users takes the value. `acceptedAttributes` (values of any shape): the named ones users takes, frozen; an email's verification only beside the email. `isWellFormedSubject`: a subject's shape.
- `usersImport`, called by the app entry `users-import` (`settle-records`): a record brought from another IdP, kept through the ledger's `keep` and as a verified contact; its shape and answers: internal module `imports`. No passkey is brought.
- `./testing`: contract tests for users, user ledgers and the Store interface, configuration builders, and the Store interface in memory.

## Invariants
- A subject is 1 to 255 ASCII characters: one outside that refuses boot in the settings (the identifier's, where `subject` is left out), is unavailable in a ledger's answer, and is none when looked up without asking the ledger.
- Identifiers match exactly, never folded or trimmed, and a password as typed, with no Unicode normalization; an empty identifier or subject, or an identifier past 255 bytes (a fixed guard), is none, and the ledger is not asked; `create` throws TypeError on either identifier, and the settings refuse one past 255 bytes.
- A password check waits as its identifier's failures say, an unknown identifier as a known one, at most 4 checks of one identifier held, so at most 4 × `longest`; one more is Unavailable, unchecked (internal module `waits`).
- Boot is refused on identifiers that differ only in case, Unicode normal form or surrounding whitespace, on two identifiers with one subject, and on more than one ledger or a ledger beside `registered` users.
- Unanswerable is never read as none: claimed contacts are then unanswerable. `verifiedContact` for an erased subject: internal module `stores`.
- A contact is kept once per subject by its `canonicalAddress` form, as first given, up to 20 (a fixed capacity guard: no subject needs more), and another past them throws RangeError; an empty subject or contact value throws TypeError.
- Attribute values: `email` one `isAddress` takes that is also RFC 5322's addr-spec in ASCII (a dot-atom local part, LDH labels), `picture` an https URL that reads back as given, `email_verified` a boolean, `name` text holding more than blanks, `groups` a list of text, no text with a control or format character; another refuses boot in the settings, and from a ledger is left out, its name logged.
- `email_verified` holds only beside `email`: without it, boot is refused in the settings, and a ledger's is left out, as it is with an email left out.
- A password hash is one `secret-hash` reads (bcrypt or scrypt), else boot is refused; a password over 1024 bytes is none before any computation or ledger call (fixed, to guard hashing, far past NIST SP 800-63B's 64-character floor), and `secret-hash` decides the rest, within its assembly's `max-concurrent`. Each verification does the work of every kind of hash in use, so timing does not tell whether a user exists.

## Depends on
- `kernel`, `mail-address`, `secret-hash`, `erasure-extensions`

## Vocabulary
- user: a subject and frozen attributes. user ledger: the outside system that holds users.
- verified contact: a way to reach a user that the user has shown is theirs. claimed contact: the user's `email` attribute, as the settings or a ledger state it, apart from verified contacts.
