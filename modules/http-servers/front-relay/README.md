# front-relay

## Responsibilities
- Serves the Front's routes and relays to the Core the operations `front-core-wire` carries over HTTP: the adapter of the http axis a Front composes. It holds no key, no state and no policy of the Core's.
- Tells the Front's readiness whether the Core is reached.

## Not here
- Reading requests, the Front's own routes and their policies, the security headers and cross-origin answers: `http-server`'s `nodeHttpServer`, whose fallback this is.
- Each operation's path, fields and status, and the frame: `front-core-wire` and `front-core-codec`. Adding an operation changes those and its owner, never this.
- What a field means, and every check past its length and characters: the Core's.

## Offers
- Composition definition (`./module`): the server of `http`'s `httpServers`, and the probe `core` (kernel's `probes`). It reaches the Core over TLS (`network`: `wire`).
- Operator section `front-relay`: `core-host` and `core-port` (the Core's entrance), `server-name` (what the Core's certificate is checked for, `core-host` unless set), `certificate-file` and `key-file` (this instance's), `core-authority-file`, and `timeout`.
- `./testing`: `wireCertificates`, the wire's test certificates made by openssl, and `frontRelayConfig`, the section with them.

## Invariants
- A request a route of the Front takes is that route's, one taking a relayed path among them, exactly or by a wildcard: warned `front-relay.shadowed` at boot, never refused. Any other is the operation the protocol names at its method, path and discriminator, sent to the Core as its frame, or a fixed `404`; a probe route is never relayed.
- Each frame carries as its declared source the source the Front's `http.trusted-proxies` determined, none where it is undetermined, never a value the request names: the Front's declaration, which the Core counts by while the Front is honest. It applies no policy to what it relays: the Core does.
- A body of another type than the operation's is `415`, and a field the frame cannot carry (a name sent twice, a field sent as a JSON member of no text, a value outside its spec; a member under a name the wire gives no field is ignored) `400` `invalid_request` naming the field, never the value; neither sends anything.
- The Core's `ok` is the operation's success status with its body as JSON, a refusal its word's status with `error` and `error_description` (a limit's `429` with `Retry-After`), its DPoP nonce as `DPoP-Nonce`, all kept out of caches; a frame the Core rejected is `502`, logged `front-relay.rejected` by its code.
- No connection, no reply within `timeout`, or a connection lost is kernel's `Unavailable` (`core`), answered `503`; a reply that is no frame closes the connection, logged `front-relay.reply_unreadable` by its code.
- A page of a listed origin (`http.cors-origins`) calls across origins only the operations the protocol says a page of another origin calls.
- Boot is refused where a file the section names cannot be read.
- One connection at a time, connecting when first needed; each connection reads the files anew and is held to `tls-options`' floor, checking the Core's certificate against `core-authority-file` alone.
- It holds only its own connection, so it is safe on many instances.

## Deployment
- The Core's entrance (`core-wire`) at `core-host` and `core-port`, reached from the Front's network alone: the Front's egress is that port and no other destination of the Core's.
- `certificate-file` and `key-file`: this instance's own short-lived certificate (workload identity), issued by the authority the Core takes, naming the instance by a URI SAN; replaced in place as it rotates.
- `core-authority-file`: the authority issuing the Core's certificate, a private one for this wire alone.

## Depends on
- `http` and `http-server` (the server and its fallback), `front-core-wire` and `front-core-codec` (the operations and the frame), `tls-options` (the floor), `kernel`, `zod`.

## Vocabulary
- relay: send a request the Front does not answer to the Core as its frame, and answer the reply.
