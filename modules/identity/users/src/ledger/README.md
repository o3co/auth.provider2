# ledger

## Responsibilities
- Reads a contributed user ledger's answers into users' own: verification, a user by subject or unanswerable, a user by identifier where the ledger looks users up so, a create where the ledger makes subjects, an identifierless create where it makes identifierless ones, and a `keep` where it takes imports.

## Not here
- Links, contacts and which answer users gives: users' own.

## Offers
- `contributedSource(ledger, log)`: the ledger as a source of users; `byIdentifier`, `create`, `createIdentifierless` and `keep` only where the ledger has them.

## Invariants
- A ledger's answer is read once into a frozen copy of `subject` and `attributes`; its failure, an ill-formed subject, attributes that are no object, or another subject's user is unavailable, never none.
- Every user answered holds a well-formed subject, else unavailable; a lookup by an ill-formed subject, or an empty identifier is none, and the ledger is not asked; a create for an empty identifier throws TypeError, unasked.
- A create answers `exists`, or `created` with a user read as any answer is; any other answer is unavailable. An identifierless create answers a user read as any answer is, else unavailable. A `keep` answers `kept` or `conflict`; any other answer, or a failure, is unavailable.
- Attributes users does not take are left out, each logged by its name alone.

## Depends on
- None (users' contract)
