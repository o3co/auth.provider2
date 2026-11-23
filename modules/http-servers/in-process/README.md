# in-process

## Responsibilities
- Serves every route of a composition holding the Front's modules and the Core's in one process, for development and trials: the adapter of the http axis such a composition names.
- Declares where it stands on the promises a compromised Front must not break.

## Not here
- Reading requests, applying the routes' policies and writing answers: `http-server`'s `nodeHttpServer`, which this contributes as it builds it.
- A Front apart from the Core, and the wire between them: the other adapters of the http axis (`front-relay`, `core-wire`).
- Refusing a deployment that requires those promises: `promises`, by its stance.

## Offers
- Composition definition only: the server of `http`'s `httpServers`, and two stances (`promises`' `stances`).
- It is not the axis's default: a development composition names it to compose it.

## Invariants
- Every route is served on the one listener, a probe route as any other; a request no route takes is `404`, or `405` naming the methods its path takes.
- Every request reaches its route as `http-server` reads it from the connection's bytes: no value passes between the Front's modules and the Core's but serialized as HTTP.
- It stands breaking `front-compromise-new-authorization` and `front-compromise-client-token`: the Core runs in the Front's process, so whoever takes the Front takes the Core with it, its checks and the use of its keys; a deployment requiring either is refused boot by `promises`.
- It holds nothing beyond its listener, so it is safe on many instances.

## Depends on
- `http`, `http-server`, `promises`, `kernel`.
