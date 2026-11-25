# core-wire

## Responsibilities
- Serves the Core's routes to the Front over the Front to Core wire: the adapter of the http axis a Core composes. It ends the wire's mutual TLS itself, hands each frame to the route its operation names, the route's policies first, and replies.
- Serves the probe routes on a listener of their own, and holds the detection line: a frame no honest Front sends.

## Not here
- The frame, the operations and how each is carried as HTTP: `front-core-wire` and `front-core-codec`. HTTP from browsers and clients: the Front's (`front-relay`).
- The routes, the policies, the marks and the rule routes are guarded by: `http`. The probe listener's HTTP: `http-server`'s `nodeHttpServer`.
- What a field means, and the failures of its evidence or end-to-end cryptography: the route's, counted by it, never a violation.

## Offers
- Composition definition (`./module`): the server of `http`'s `httpServers`. It ends TLS for the wire (`network`: `serves-wire`); its probe listener is `http-server`'s.
- The axis's default, as the strong side: a composition that names no adapter of the http axis composes it.
- Operator section `core-wire`: `certificate-file` and `key-file` (the entrance's), `front-authority-file`, `probe-host` and `probe-port`, and `on-violation` (`notify`, the default, or `cut`).
- `./testing`: `coreWireConfig`, the section with a test's certificates and the probe listener on a free port; `wireClient`, a Front's connection on localhost showing a certificate (`FrontCertificates`) or none, sending frames and keeping the replies by id.

## Invariants
- The wire listens on `http`'s host and port, at most `max-connections` at once, held to `tls-options`' floor: only a Front whose certificate chains to `front-authority-file` connects, and its connection closes as that certificate expires. A handshake refused is logged at debug alone, as anyone on the network can cause one.
- A frame is handed to the POST route at its operation's path, rebuilt as `front-core-codec` writes it: a form, or a JSON object of strings, with the headers carried. Its source is the one the Front declared, read as an `X-Forwarded-For` the Front sent: the Core's `http.trusted-proxies` names the Fronts, and none declared leaves the source the Front's, undetermined. It is the Front's declaration, so what counts by it holds only while the Front is honest.
- The route's policies apply first, and a body it does not take is `415` after them; Unavailable is answered as the route declares, warned `http.unavailable`, and any other failure is `500`, logged `http.failed` by kind; each frame's end is told to `requestEnds`.
- The operation's success status with JSON replies `ok` with the body and a `DPoP-Nonce`; a status of 400 or more with an `error` the wire names (a limit's among them) replies that refusal, its `error_description` the detail (control characters as spaces, cut to 400 bytes) and its `Retry-After` in seconds; `503` replies `temporarily_unavailable`. Anything else, and an operation no route takes, reply `server_error`, warned `core-wire.unrelayable` (route, status) or `core-wire.no_route` (kind).
- A frame the codec rejects is answered with its code alone, and its connection ends, nothing read after: a violation, warned `core-wire.violation` with the Front instance's id and the code; a version not taken is warned `core-wire.version_refused`, never a violation. Each instance's warnings of one event are one line a minute, the next saying how many were `held`.
- Under `cut`, an instance that sent a violation is cut (`core-wire.cut`): its connections close, and the process refuses it until it restarts (`core-wire.cut_refused`); a certificate naming no URI, whose id would change with the next one, is refused (`core-wire.unnamed_refused`). The instance's id is its certificate's whole first URI name, else its CN, else its fingerprint.
- A cut holds in the process that made it alone: it is neither shared among the Core's instances nor told to the certificates' authority; sharing it needs a list of cuts the store keeps whole, which is the store's gate to decide.
- A route declaring `exposure` `probe` is served on the probe listener alone; every other route only through the wire.
- Boot is refused where `http`'s `guardedRoutes` refuses, an operation's route takes no body of the operation's, or a file the section names cannot be read; an ordinary route no operation reaches is warned `core-wire.unreached`. A start that fails leaves no listener open.
- It holds its listeners and the cuts it made, so it is safe on many instances.

## Deployment
- `certificate-file` and `key-file`: the entrance's certificate for the name the Fronts reach it by; `front-authority-file`: the authority issuing each Front instance its own short-lived certificate, naming it by a URI SAN.
- The wire's port reached from the Fronts' network alone; the probe listener from the orchestrator's alone.

## Depends on
- `http` (its routes and `./server`), `http-server` (the probe listener), `front-core-wire` and `front-core-codec`, `tls-options` (the floor), `request-source` (the address's form), `kernel`, `zod`.

## Vocabulary
- violation: a frame an honest Front, encoding by the same codec, never sends.
- cut: refusing a Front instance's connections after its violation.
