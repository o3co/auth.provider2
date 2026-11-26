# built-in

Internal module of `token-endpoint`: what the package contributes of its own, the composed rule for a request's audience and its stance on the promises.

## Responsibilities
- The one rule for the audience a request asks for, from what `targetRules` holds.
- The stances the package contributes, those on the client's own token and on a client's token held to a key derived from what the grants declare, never from their names.

## Not here
- Handling the request (`route`) and what a grant issues through (`issuance`).

## Offers
- `composedRule` (the build context) → the one rule contributed to `targetRules`, or `unread` (the default audience, the request unread) when none is; two refuse boot.
- `tokenEndpointStance`: `core-compromise-contained` holds by `token-endpoint`, as issuing access tokens asks of its taker.
- `clientSubjectStance` (the grants composed) → `no-client-subject-token` by `token-endpoint`: held where every grant declares `user`; broken where any declares `client` or no kind, the reason naming each such grant type and, where `grants`' `grantServers` lists it, the module serving it.
- `keyHoldStance` (the grants composed) → `front-compromise-client-token` (claim 2) by `token-endpoint`: held where every grant declares a `keyHold`, its reason each one's (the key its authorization named ahead, its family's key, or the key that signed its assertion); broken where any declares none, or a value no hold is, its grant type named. The methods' keys are `clients`' stance.

## Depends on
- `grants`, `kernel`, `promises`; the package's contract.
