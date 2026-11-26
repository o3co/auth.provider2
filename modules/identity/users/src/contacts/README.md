# contacts

Internal module of `users`: the verified contacts it keeps for a subject, and their form.

## Responsibilities
- Keeps a contact verified or brought, once per subject by its canonical address, at most 20; reads a subject's contacts back.

## Not here
- The store of contacts and its eraser: internal module `stores`. Which contact to verify, and when: the caller's.

## Offers
- `keptContact` (the store, `verified` or `brought`), `contactsIn` (a stored record → its contacts), `contactSubjectOf` (whose a record is, for the eraser).

## Invariants
- A contact is an email address mail takes (`mail-address`'s `isAddress`: 254 bytes at most, no blank, quote, backslash or control character; an internationalized one taken, as an import brings it); keeping another is a TypeError, nothing written. The read is checked too: a stored one not of that form, as another version may have written it, is not read.
- Why the form: a passkey's creation shows the address a subject verified last, masked, as its account, and the Front's wire carries that statement at a fixed bound, so the address's form bounds the statement's size.

## Depends on
- `mail-address` (an address's form and its canonical form), the package's contract and its store interface.
