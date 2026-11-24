# caller

Internal module of `token-endpoint`: calling a contributed grant directly, as the endpoint does once a request has passed it, for the tests of the modules that contribute grants.

## Responsibilities
- Builds the input a grant is handed from a client, its parameters, a binding what the grant identified (`identified`) and what the client's authentication verified (`authenticated`), and calls the grant through the endpoint's own checks of a mistyped parameter and an untargeted request.

## Not here
- Authenticating the client, allowing the grant and reading the binding (`route`, checked in its tests). The targets rule (`built-in`).

## Offers
- `grantCaller` (a module providing `grantCalls` and the composed targets rule), `grantCalls` (the contract: `call`) and `grantInput` (the input alone), which `./testing` hands out.

## Invariants
- A form holds strings only; a JSON body takes any value, a non-string one read as mistyped, as the endpoint reads it.
- A refused issuance comes back as the endpoint's error, and an issued answer's body as the endpoint writes it.
- Its `issue` signs through `tokens` at once, the bundle recorded nowhere: recording is the endpoint's own step, checked in its tests. It is given `tokens`' `admits`, `prepare` and `sign`, and its revoking by reference (`CallerTokens`), and says the endpoint's stance.

## Depends on
- `clients`, `grants`, `http` (the request type), `kernel`, `promises`, `sender-binding` (the binding type), `tokens`; `route` (the grant's input, the mistyped refusal, the refused answer, the answered body), `built-in` (the targets rule, the stance)
