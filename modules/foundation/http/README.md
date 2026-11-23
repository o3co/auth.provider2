# http

## Responsibilities
- Owns the HTTP entry point: the routes that modules contribute, the words they are written in, the policies routes use and the marks they are checked against, and the section the one server serves by.
- Hands the routes to the one server contributed (`httpServers`) at start, and drains it at stop.

## Not here
- Reading requests, refusing boot on what `guardedRoutes` finds, applying the guards and writing answers (the server's: the composition's adapter of the http axis contributes it).
- What a route means and its error vocabulary (the contributing module's); what a policy decides and answers (its owner's).
- Any name taken from request headers: the public origin comes only from configuration.

## Offers
- `routes`: a method, a path and a handler, with the policies used (and their options), the bodies taken and cross-origin use when declared; how paths match, HEAD, and `unavailable`/`noted` are in `Route`'s doc comment.
- A route's `exposure` (`Exposure`): the listener that serves it, `ordinary` unless it says `probe`, a check of this instance; a server with a probe listener, one that serves such checks and nothing else, serves it there alone, and one without serves it as any other route.
- Policies, their rules and the marks (internal module `policies`): `policy`, `use`, `policies` (`applying` makes a `PolicyRule`), and `marks` (`PolicyMark`, one per `RouteGuarantee`).
- A route says whether it changes state (`changesState`), and, changing it, why it takes other sites' requests (`crossSite`) or any number from one source (`unlimited`).
- The request type, with its source; `Values`: values with the same name keep the order sent, `single` gives a name's only value, `repeated` the names with more; whether one must be single is the route's.
- `loads`: what a page declares it loads (the origins it frames, its inline scripts, and whether its forms post to this origin).
- `listening` (the port) and `site` (the public origin; cookies can be made secure unless it is http, which boots only with `insecure-origin`; `proxied`, whether `trusted-proxies` names a proxy, without which no request's scheme is https); `client-certificate`'s `certificateForwarding` is provided from this section.
- The section's other keys, each described in the settings list: `host`, `port`, `public-origin`, `cors-origins`, `headers-timeout`, `request-timeout`, `max-connections`, `proxy-hops`.
- `requestEnds`: each request's end, once, answered or closed: the method sent, the declared path of the route reached (none when none), the status written or `closed` when the client closed first, the milliseconds taken (never negative), and `fallback` where a server's fallback took it; its observers are told after the request, asynchronously, and what they throw or reject is dropped.
- `httpServers`: the one server, given the declared routes, the settings, the observers, the log and the clock at start, and drained at stop.
- `jsonAnswer`: status, a JSON value, and any cookies and headers → an answer kept out of caches (`noStore`), but where the headers given replace its `cache-control` or `pragma`.
- `./server`, kept for the servers its `takenBy` names: `valuesOf` (a map), `fieldsOf` (a JSON object's members: its strings the fields, the others `mistyped`) and `readOnly` (a map whose writes throw), which make a request's values; `guardedRoutes`, the routes guarded by the rules (`GuardedRoute`) or why boot is refused (`GuardedRoutes`; internal module `guards`).
- `./testing`: `httpConfig` and `testRequest`, test configuration and request builders with working defaults, read-only as a server gives a request.

## Invariants
- Boot is refused when two routes take one method and path, when two marks name one guarantee, or when no server, or two, is contributed: a composition with `http` and no adapter of the http axis contributing its server is refused, the refusal saying to compose one.
- Every start under `insecure-origin` is warned of, as `kernel` warns each value a production deployment refuses: the session's cookie goes in the clear.

## Depends on
- `kernel`, `request-source`, `client-certificate`, `url-setting`.
