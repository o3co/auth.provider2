# method

Internal module of `client-assertion`: the `private_key_jwt` method, how it reads a request's assertion and judges it.

## Responsibilities
- Reads a request's assertion, its client and its claims, judges its audience against `issuer`'s URL, and spends its `jti`, as the method `clients` dispatches to; made from the build context, a public origin required.

## Not here
- What the method declares, how a refused request is marked, the lifetime and the spent `jti`s' keeping: the package's card. The client's keys and a loose audience's setting: internal module `keys`. Checking the JWT itself: `external-jwt`.

## Offers
- `assertionMethod` (`Parts`: the spent assertions, `external-jwt`, `issuer`'s URL, the token endpoint's URL, the lifetimes, the algorithms, the clock and the log) → the `AuthMethod`; `assertionType`, the assertion type it takes.
- `methodEndpointIn` (the build context) → the token endpoint's URL, refusing boot without a public origin or that location; `methodIn` (the build context, that URL) → its `Parts`; `methodTakes`, which its package names among its own takes.

## Invariants
- The three values are read from the body only, a form or a JSON object; never from the query.
- Only one of the two, an empty `client_assertion`, or either part or `client_id` given twice or, in JSON, not as a string is malformed credentials, before anything is judged or spent. An assertion type other than `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` is refused, never left to another method.
- `client_id`, when given, names the client; otherwise the assertion's `iss` does. `iss` and `sub` are the client's id.
- `aud` is `issuer`'s URL as one string, judged before the `jti` is spent: the token endpoint's URL, or a list, could be for another authorization server that names this one's token endpoint.

## Depends on
- `clients` (the method's shape), `external-jwt`, `http` (the request, the site), `issuer`, `token-endpoint` (its location), `kernel` (the build context, the clock, the log), `jose`, `zod`; the package's spent assertions, section, `verifiedOf`'s proof and `said`; internal module `keys`.
