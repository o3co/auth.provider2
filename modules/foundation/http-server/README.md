# http-server

## Responsibilities
- Builds a server of `http`'s routes on Node's HTTP (`nodeHttpServer`): reads each request, applies the policies its route uses, and writes the answer.
- Reads what a request sends (query, form, JSON, headers) once at the boundary into read-only maps; a query or form whose percent-escapes decode to invalid UTF-8 is refused with `400`.
- Answers Unavailable from a route's policy or handler with the route's declared answer, else `503` `service_unavailable`: retryable, kept out of caches (`noStore`: `no-store`, `Pragma: no-cache`).
- Applies the routes' policies itself, as `http`'s `Route` promises of every server: a server built here keeps them wherever it is composed, and where no rule is contributed, no route uses a policy.

## Not here
- Contributing the server: the composition's adapter of the http axis contributes to `http`'s `httpServers` the one `nodeHttpServer` gives, or refuses boot with the refusals it gives instead.
- What to do with a request no route takes, and which of those take cross-origin calls, when a fallback is given (its caller's).
- The routes, their declarations and the words they are written in; the policies, their rules, the marks and the rule routes are guarded by; the `http` section, `site`, `listening`, start and stop (`http`).
- What a route means and its error vocabulary (the contributing module's); what a policy decides and answers (its owner's).

## Offers
- `nodeHttpServer` (`NodeServerParts`: the routes, rules and marks collected from `http`'s points, and a `Fallback` when given) → `NodeServer`: the server, its routes guarded once by `http`'s `guardedRoutes`, or the refusals; its start rejects other routes than those.
- A fallback, where given, takes every request no route takes, by path or by method alike, in place of `404` and `405`, after its body is read: an unknown path's POST can get `413` or `415`, not `404`. Without one, those stand.
- A fallback's `cors` names the methods and paths it takes across origins: the server answers their preflights where no route of the path takes the method asked, and lets a listed origin read every answer to them, its own `413`, `415`, `503` and `500` too (a `500` replacing an answer it cannot write among them). It is asked for HEAD as HEAD; where it throws, the request is answered as the fallback's failure, with nothing to read by.
- Bodies: a route may take a form, JSON, none, or several, and any other body is `415`, refused only after the route's policies have seen the request.
- A form and a JSON body share one size limit of 64 KiB: a larger form is read as empty, and a larger JSON body is `413`.
- A JSON body is one object in well-formed UTF-8, frozen, naming no member twice in one object; anything else is `400`.
- A request's fields are its body's values by name, in the order sent; a JSON member that is not a string is told apart as `mistyped`.
- Cross-origin routes: a preflight is answered before the policies, and answers vary by `Origin`, naming the request's origin only when listed, never `*` and never with credentials; a route's own `access-control-*` headers pass as it wrote them.
- A preflight from a listed origin, for a method a declared route takes, names the methods of the path's declared routes, the request headers the route takes, and a max age of 600 seconds.
- Any other preflight on such a path gets `204` with nothing to read by.
- `loads`: what a page declares it loads; its answer's policy allows those and nothing else, and a frame a policy cannot name makes the answer `500`.
- An answer's `cookies` are sent one `Set-Cookie` each; each request's end is told to `requestEnds`' observers, as `http`'s card says, with `fallback` where the fallback took it.
- A client certificate is read only as a trusted proxy forwards it; one from a peer not trusted is ignored, with a warning once a minute.
- `./testing`: `testServer`, a test's module contributing the one server built here, with the fallback given, refusing boot as an adapter does.
- Composition definition: none; it contributes nothing itself.

## Invariants
- Serves requests (`network`: `serves-http`), on the host and port, behind the proxies, with the origins and the limits `http`'s section gives.
- Serves every route `http` hands it on its one listener, whatever its `exposure`.
- Every answer it writes carries the security headers, set in one place: a Content-Security-Policy whose default source is none, taking scripts, styles, images and fonts from this origin (styles and fonts also over https) and letting no one frame the answer, HSTS, `nosniff`, `X-Frame-Options`, `Referrer-Policy: no-referrer` and the cross-origin ones; a route's own values of them, its policy included, are replaced; only `loads` widens a page's policy.
- Stop refuses new connections and closes idle ones; requests in flight finish (`Connection: close`) until its deadline cuts them.
- A request target not read as an origin-form path gets `400`, an answer whose headers cannot be written gets `500`, no request stops the process, and error answers never show exception text or internal values.
- Without a fallback, a path no route reaches gets `404`, and a path whose routes take other methods gets `405` naming them in `Allow`.

## Depends on
- `kernel`, `http`, `request-source`, `client-certificate`.
