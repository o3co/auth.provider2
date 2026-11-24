# imports

Internal module of `users`: a record brought from another IdP, kept as users and its ledger hold it.

## Responsibilities
- Reads one record and keeps its parts: the identifier for the subject through the ledger's `keep`, then the email as a verified contact.

## Not here
- Reading records from a file or a stream, counting answers and what a run writes: `app-entries`' `settle-records`.
- How a ledger holds an identifier: the ledger's `keep`. Passkeys: none is brought.

## Offers
- `usersImporter` (users, the ledger's `keep` or none) → `usersImport`'s `record`.

- The answers: `imported`, `conflict` (the ledger holds the identifier or the subject otherwise), `outside` (an identifier given, and the ledger takes no import), `malformed` and `full`.

## Invariants
- A record is an object of `subject` (a well-formed subject), `identifier` (a non-empty string, optional) and `verifiedEmail` (an address `mail-address` takes, optional), read once; any other key or shape is `malformed`, asking no one.
- The identifier is kept first: `conflict` or `outside` writes nothing of the record. A run done again answers `imported` where every part is held as given.
- A subject past its contacts is `full`; any other failure is thrown, unavailable where the ledger or the store fails.

## Depends on
- `mail-address` (`isAddress`); users' contract
