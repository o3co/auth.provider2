# conformance-front

## Responsibilities
- Puts an https front before a running app, as a deployment's proxy is, for a harness whose outside party (a conformance suite, a client library) reaches the app over https.

## Not here
- What a harness answers or changes itself (a login page, a request rewritten): its own, through the hooks.
- Starting the app (the harness's), and judging a client's certificate (the app's).

## Offers
- `startFront`: an https server at `listen`, one per origin a harness needs (each takes its own port), speaking the TLS the harness narrows it to where it does (its lowest version, its ciphers), on a port it takes, whose origin is `https://<publicHost>:<port>`; the app is reached at `upstream()`, read for each request, so the front starts before the app and its origin can be the app's public origin.
- Hooks: `handle` answers a request at the front, `rewrite` gives the URL and body it goes on with, `answered` is told each answer of the app's with its request as it begins, `finished` each one whole, its body as it passed, once the app's answer was read to its end (never for one the app cut off).
- `sender`: the address the app is told the request came from, in place of the peer's, for a client on this machine whose loopback address the app takes for its trusted proxy.
- `clientCertificate.header`: each client is asked for a certificate, and the one presented goes on URL-encoded as PEM in that header.
- `selfSigned`: a P-256 key and a self-signed certificate naming a host and loopback, made by `openssl`; the curve is named, never written as explicit parameters, which Java's TLS refuses. An `openssl` still running past `timeoutMs` (30 seconds unless given) is killed, and the call fails saying so.

## Invariants
- The app is told the scheme (`X-Forwarded-Proto: https`) and the sender's address (`X-Forwarded-For`: `sender` where given, else the peer's) alone: those a client wrote, `Forwarded` and `X-Forwarded-Host` are dropped, and so is a client's own certificate header.
- A body goes on with its length as rewritten. A connection's own headers (`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, the proxy ones) and those a `Connection` header names, in any case, are never passed, to the app or back.
- An answer the app cuts off midway ends the client's answer too.
- A certificate is carried, never judged.
- It speaks no TLS below 1.2, whatever it is given. A cipher list of TLS 1.2's names narrows 1.2 alone: TLS 1.3's suites change only where the list names them (`TLS_…`).
- While the app cannot be reached, and where `handle`, `rewrite` or `answered` throws, the answer is `502` (a throw in `finished` changes no answer, given already); where the app's answer breaks after it began, the client's answer is ended instead.
- An app that says nothing for `appTimeoutMs` (30 seconds unless given) is cut off: before its answer began, the front answers `504`, saying the app did not answer; after, the client's answer is ended.

## Depends on
- The `openssl` program on the path, for `selfSigned`. No workspace package.
