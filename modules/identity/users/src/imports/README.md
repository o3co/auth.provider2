# imports

Internal module of `users`: a record brought from another IdP, kept as users and its ledger hold it.

## Responsibilities
- Reads one record and keeps its parts: the identifier for the subject, with its password's hash where given, through the ledger's `keep`, then the email as a verified contact.

## Not here
- Reading records from a file or a stream, counting answers and what a run writes: `app-entries`' `settle-records`.
- How a ledger holds an identifier: the ledger's `keep`. Passkeys: none is brought.

## Offers
- `usersImporter` (users, the ledger's `keep` or none, the work of the passwords it holds or none) → `usersImport`'s `record`.

- The answers: `imported`, `conflict` (the ledger holds the identifier or the subject otherwise), `outside` (an identifier given, and the ledger takes no import; or a hash given, and its `keep` takes no hashes of the hash's work), `malformed` and `full`.

## Invariants
- A record is an object of `subject` (a well-formed subject), `identifier` (a non-empty string, optional), `passwordHash` (a hash `secret-hash` reads, given only with an identifier, optional: one of a form it does not read, argon2 or PBKDF2 among them, is `malformed` too) and `verifiedEmail` (an address `mail-address` takes, optional), read once; any other key or shape is `malformed`, asking no one.
- The identifier is kept first: `conflict` or `outside` writes nothing of the record. A `full`, or a failure of the contact store, after it leaves the identifier kept; a run done again keeps nothing twice and answers as the rest stands, `imported` once every part is held as given.
- A record with no identifier keeps its email as the subject's verified contact without asking the ledger, whether or not the ledger holds the subject.
- A subject past its contacts is `full`; any other failure is thrown, unavailable where the ledger or the store fails.

## Depends on
- `mail-address` (`isAddress`), `secret-hash` (`readSecretHash`); users' contract
