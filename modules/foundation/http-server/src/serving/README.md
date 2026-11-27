# serving

Internal module of `http-server`: the server that answers each request with the route it reaches.

## Responsibilities
- Reads a request's head, finds the route its path reaches, has the route's policies and handler answer, or the fallback where no route takes it, and writes the answer.

## Not here
- What a request's body holds (`bodies`), the routes' guards (`http`'s `guardedRoutes`), cross-origin answers (`cors`), the security headers (`security-headers`), and telling a request's end (`ending`).
- Checking the segments a `*` takes: its handler checks them by its own rules.

## Offers
- `serve`: the routes, guarded by their policies, answered on a Node HTTP server, with the fallback when given.
- `drain`: stops the server, cutting what is left once the stop's deadline passes.

## Invariants
- Paths: a middle `*` segment takes exactly one non-empty segment, and a last `/*` everything under it; of the declared paths reaching a path, the one with a literal at the first segment they differ comes first, and a middle `*` before a last.
- A handler reads the URL parser's path (dot segments resolved, percent-encoding kept as sent).
- A GET route that changes no state also answers HEAD, with the same headers and no body; for one that changes state, HEAD is `405`.
- A path no route reaches gets `404`, and a path whose routes take other methods gets `405` naming them in `Allow`.
- A preflight to a cross-origin route is answered before the policies and the fallback.
- With a fallback, a request no route takes, by path or by method, is its: its body read as a route taking a form, JSON or none would (any other `415`); Unavailable from it is warned `http.unavailable` with the path and answered `503` `service_unavailable`, any other failure `500`, logged by kind only.
- A preflight for a method no route of the path takes, which the fallback's `cors` names, is answered by that rule for that method alone; every answer to a request it names, the `500` replacing an unwritable one too, is made readable by a listed origin. A `cors` that throws is answered as the fallback's failure, with no rule.
- A body the route does not take is refused only after the route's policies have seen the request.
- The request a policy or handler gets is frozen, and its maps cannot be written to.
- A policy's or handler's failure is logged by its kind only, never its message.
- Unavailable from a policy or handler is warned once, `http.unavailable`, with what was unavailable, the route's declared path and the fields its `noted` gives; the answer is the route's declared one, else `503` `service_unavailable`.
- Any other failure is answered `500` and logged as a warning, `http.unexpected_failure`, by the route reached (when known) and its kind only, never its message.
- A request target not read as an origin-form path, or whose query is not well-formed UTF-8, gets `400` before any route.
- An answer whose headers cannot be written gets `500`, with none of its own headers.
- A JSON answer (`{ json }`) whose written JSON holds a null inside it, as `http`'s `writtenJson` finds one, gets `500`, with none of its own headers; `http.failed` names their paths (`null_member`), never their values.
- An answer's length is stated in bytes, so a HEAD answer carries the length its GET would.
- A request's headers must arrive within `headers-timeout` and the whole request within `request-timeout`, else it is answered `408` and its connection closed; a connection past `max-connections` is closed as it arrives.
- Stop refuses new connections and closes idle ones.
- A connection is closed only after what it still has to send, so stop never cuts an answer already written; one sent as keep-alive before stop is closed once it is sent.
- Requests in flight finish (`Connection: close`) until stop's deadline cuts them.

## Depends on
- `http` (its contract, and `readOnly` and `writtenJson` on `./server`), `kernel`, `request-source`, `client-certificate`; `bodies`, `cors`, `security-headers`, `ending`.
