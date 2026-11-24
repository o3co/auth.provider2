# endpoint-in

Internal module of `token-endpoint`: the endpoint's handler, built over what the assembly gives.

## Responsibilities
- Takes the contracts the handler works over from the assembly, and the grants composed by type, and builds the handler.

## Not here
- Handling a request, from the request to the answer (`route`). Which grants are composed, and the route's declaration (the package's module).

## Offers
- `endpointIn` (the build context, the grants composed) → `route`'s handler over `clients`, `tokens`' two handles and its issuance fencing, `grants`' session issuances and audience rule, `sender-binding`'s readers and required bindings, `audit`, and `bundle`'s run over `transparency` and the log's digest, each request's evidence read once.

## Invariants
- A grant is found by its grant type; nothing else is decided here.
- The owner looks at its bundle's judgment for about 3 s, its waits growing from 10 ms to 200 ms. An op id's fresh ground is random, counted on the instance besides.

## Depends on
- `kernel` (the build context), `audit`, `clients`, `grants`, `sender-binding`, `tokens`, `transparency`; `route`'s handler, `bundle`.
