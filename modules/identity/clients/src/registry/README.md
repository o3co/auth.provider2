# registry

Internal module of `clients`: the registry every taker shares, reading records, looking clients up and authenticating them.

## Responsibilities
- Reads a registered or a source's record into a frozen client, holding it to its sections, and answers `find`, `listed`, `checkRecord`, `bare` and `authenticate` over the methods composed.

## Not here
- The built-in methods (the package's `methods`). The sections a record holds (their owners').

## Offers
- `registry` (the registered clients, the sources, the methods, the sections) → `Clients`; `readRecord`, `clientRecord` (the registered record's schema), `methodIssues`.

## Invariants
- A registered client wins over the same id from another source.
- An id that is empty, over 256 UTF-16 code units (a fixed bound: an id is also a store key, and every reader of an id holds it to this one), with a lone surrogate, or with a C0, DEL, C1, U+2028, U+2029 or BOM character is unknown, and no source is asked; registered, it refuses boot.
- `listed` takes the id of each record a source lists (`ClientSource.listed`), none where it cannot be read, and answers each id once as `find` does, from the first source that names it: one `find` answers none for, or a record that fails, is left out, and a registered client's id never.
- A source's client is `signed` only where that source declares `signed`, a declaration that puts the source in the trust it declares; a registered client, and a record `checkRecord` reads, never is.
- A record failing any section check is refused as a whole; a source's record is also refused unless it passes the registered rule, names a known method and carries the id asked, and when reading it throws.
- A source's record may name the registry version it came from, a positive whole number; the client says it. Any other value refuses the record; a registered record names none.
- A method's verification answers what it verified (`proof`), carried unread in the authenticated answer; none verified is `bad_credentials`. The answer is marked `assertion` where its method authenticates by an assertion, and by no other's `proof`.

## Depends on
- `http` (the request), `kernel` (freezing), `zod`; the package's contract and `methods`.
