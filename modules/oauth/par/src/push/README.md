# push

Internal module of `par`: the pushed request's route handler and the `request_uri` source.

## Responsibilities
- Checks a push and keeps its JAR; reads a pushed JAR back for the client that pushed it.

## Not here
- The route's declaration and policy (the package's module).

## Offers
- `pushing` (`PushParts`) → the handler. `pushedSource` (the store) → the `request_uri` source. `parPath`, `requestUriPrefix`.

## Invariants
- A parameter sent twice is refused first, before anything else is read; the client is authenticated before its JAR is read; nothing is kept for a push refused.
- A proof refused by its kind is answered in the kind's words and headers, or unavailable where the kind could not tell; two bindings proved are refused; a `dpop_jkt` out of its form is `invalid_request_object`.
- A `request_uri` met already is a store that cannot tell: unavailable.
- A record of another shape is a store that cannot tell: unavailable.

## Depends on
- `clients`, `sender-binding`, `http`; `authorize` (the source's shape, `jarVerified`, made with `client-assertion`'s check the module gives).
