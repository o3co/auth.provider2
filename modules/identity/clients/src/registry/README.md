# registry

Internal module of `clients`: the registry every taker shares, reading records, looking clients up and authenticating them.

## Responsibilities
- Reads a registered or a source's record into a frozen client, holding it to its sections, and answers `find`, `checkRecord`, `bare` and `authenticate` over the methods composed.

## Not here
- The built-in methods (the package's `methods`). The sections a record holds (their owners').

## Offers
- `registry` (the registered clients, the sources, the methods, the sections) → `Clients`; `readRecord`, `clientRecord` (the registered record's schema), `methodIssues`.

## Invariants
- A registered client wins over the same id from another source.
- A record failing any section check is refused as a whole; a source's record is also refused unless it passes the registered rule, names a known method and carries the id asked, and when reading it throws.
- A source's record may name the registry version it came from, a positive whole number; the client says it. Any other value refuses the record; a registered record names none.
- A method's verification answers what it verified (`proof`), carried unread in the authenticated answer; none verified is `bad_credentials`.

## Depends on
- `http` (the request), `kernel` (freezing), `zod`; the package's contract and `methods`.
