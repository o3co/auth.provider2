# built-in

Internal module of `token-endpoint`: what the package contributes of its own, the composed rule for a request's audience and its stance on the promises.

## Responsibilities
- The one rule for the audience a request asks for, from what `targetRules` holds.

## Not here
- Handling the request and what a grant issues through (`route`).

## Offers
- `composedRule` (the build context) → the one rule contributed to `targetRules`, or `unread` (the default audience, the request unread) when none is; two refuse boot.
- `tokenEndpointStance`: `core-compromise-contained` holds by `token-endpoint`, as issuing access tokens asks of its taker.

## Depends on
- `grants`, `kernel`, `promises`; the package's contract.
