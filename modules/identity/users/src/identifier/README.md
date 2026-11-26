# identifier

Internal module of `users`: the form an identifier must have, wherever users reads one.

## Responsibilities
- Holds an identifier's bound and characters, for the settings, a ledger's lookups and creates, a password check and an import alike.

## Not here
- Matching identifiers (exact, never folded or trimmed) and the settings' boot checks: the package's.

## Offers
- `maxIdentifierBytes` (255, past an email's 254) and `identifierFits`.

## Invariants
- An identifier fits in 255 UTF-8 bytes and holds no character JSON writes as `\uXXXX` (no C0 control, 0x00 to 0x1f, and no lone surrogate), nor DEL (0x7f), which no one types. Non-ASCII is taken, as an internationalized address is. One that does not fit is refused in the settings, none on a lookup or a password check, and a fault on a create.
- Why the characters: the identifier is shown masked in a key's creation statement (its first character and its domain), which the Front's wire carries at a fixed bound, so its form bounds the statement's size: a character JSON writes in six would pass it.

## Depends on
- Nothing in the workspace.
