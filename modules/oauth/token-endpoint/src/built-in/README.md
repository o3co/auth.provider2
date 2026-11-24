# built-in

Internal module of `token-endpoint`: what the package contributes of its own, the composed rule for a request's audience and its stance on the promises.

## Responsibilities
- The one rule for the audience a request asks for, from what `targetRules` holds.
- The stances the package contributes, the one on the client's own token derived from what the grants declare, never from their names.

## Not here
- Handling the request and what a grant issues through (`route`).

## Offers
- `composedRule` (the build context) → the one rule contributed to `targetRules`, or `unread` (the default audience, the request unread) when none is; two refuse boot.
- `tokenEndpointStance`: `core-compromise-contained` holds by `token-endpoint`, as issuing access tokens asks of its taker.
- `clientSubjectStance` (the grants composed) → `no-client-subject-token` by `token-endpoint`: held where every grant declares `user`; broken where any declares `client` or no kind, the reason naming each such grant type and, where `grants`' `grantServers` lists it, the module serving it.

## Depends on
- `grants`, `kernel`, `promises`; the package's contract.
