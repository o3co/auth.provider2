# publish-serve

## Responsibilities
- The publisher's stand-in for development: serves the files the publishing entries wrote under one directory (`discovery-publish`, `keys-publish`), on an origin on loopback, to the pages it lets read them. Never a deployment's publisher.

## Not here
- Where each file lies under the directory, and what it holds: `discovery` and `keys`, which write them.
- A deployment's publisher, its origin, its TLS and its reader policy: the operator's.

## Offers
- `publish-serve <directory> <origin> [<reader origin>...]`: serves until SIGTERM or SIGINT, writing `serving <directory> at <origin>` on standard output; on a refusal, what is wrong on standard error, exit code 1; wrong arguments, its usage, exit code 64.
- `publishServe` (the arguments) → the lines, the exit code and, where it started, the server (`origin`, `close`), for a test or an app's script to run in process.

## Invariants
- It listens on Node's HTTP server alone (`network`: `serves-http`): the origin is plain `http`, its host loopback by `url-setting`'s `isLoopbackName`. An address is bound as written; a name under `localhost` is bound to `127.0.0.1`, never resolved. Port `0` takes a free one, named in the line it writes.
- The origin and each reader are origins as written: a path, a query or a trailing `/` refused; `*` is no reader.
- Each file under the directory is served at its path, with or without a trailing `/`, as `application/json` (its one media type, as the OpenID Connect place has no extension). GET and HEAD only, else `405`.
- Each segment names its file as written, percent-encoded as the publisher writes an issuer's path, and is judged decoded: one that is `.`, `..`, empty or holds a separator, or does not decode, is `404`. No listing.
- No file outside the directory: a file is opened never following a link, and read through that one descriptor only where it is a regular file whose real path, the same file, is under the directory; a link, a directory or a file it cannot read now is `404`, and the server serves on.
- A page from a reader origin may read (its origin echoed in `Access-Control-Allow-Origin`); from any other, nothing allows it. `Vary: Origin` on every answer.
- The directory is the operator's, written by the publishing entries alone. Its last component is held to the descriptor read; one writing the tree while it serves could swap an ancestor between the checks, as Node opens no file relative to a directory's descriptor: that writer is outside what it stands for.
- Nothing else of the provider runs in it.

## Depends on
- `url-setting` (`isLoopbackName`); Node's built-ins.
