# issuance

Internal module of `tokens`: the judgment `admits`, `prepare` and `issue` share, and the making `prepare` and `sign` do over it.

## Responsibilities
- Judges whether an access token may be issued: tokens' own rule, then the issuance policies, within one deadline.
- Makes a token over the judgment, from one frozen copy of the request and its limits: `prepare` fixes its texts, `sign` signs them and answers what is left of the token; `issue` is the two at once.

## Not here
- The token's claims, its signing, its lifetime and its cap (the package's). The policies: those composed at `issuancePolicies`.

## Offers
- `judging` (the policies, the clock, the deadline) → the judgment `admits`, `prepare` and `issue` share.
- `issuing` (the judgment, the making, the clock) → `admits`, `prepare`, `sign` and `issue`, alike for tokens and its stand-in; `MakeAccess` and `MadeAccess`, the making it takes: a token's header and claims texts, and its signing.
- `accessTokenLifetimeSeconds`: the lifetime `issue` applies where a grant gives no `lifetimeSeconds`, in whole seconds from 2 to 86400, fixed when `tokens` is built, for a grant with a ceiling to read at build time. It is not the longest life any token may have: a grant's own `lifetimeSeconds` may differ. A boot check against it does not reach tokens already issued, or instances still on other settings.
- `issuanceOf` and `checkingOf` (the access tokens built) → the members `accessTokenIssuance` and `accessTokens` hand on, each a new object holding its own members alone.
- `authenticatedAheadMs`, `issuanceTimeoutMs`: tokens' own rule's bound and the policies' default deadline.
- `issueAtOnce` (issuing, a request, limits) → `prepare` then `sign`, signed at once and recorded nowhere, for a test that needs no bundle (`./testing`).
- `refusedDescription`: the description of an issuance refused for a reason the client is not to learn, a policy's unreadable answer or a fence's refusal.

## Invariants
- The order policies are asked in: tokens' own rule first (an authentication time over 300 s ahead of the clock, a fixed allowance for hosts' clocks, as 0.17 allowed), then the issuance policies in name order, each asked the grant as its caller verified it; any answer but allowed refuses. All of them answer within `issuance-timeout` together: past it the issuance is unavailable, and the signal each policy is given aborts.
- A policy reads session-built state late (`c.late`), else boot cycles.
- `admits` makes the same judgment without making a token, but for the lifetime, which only the limits and signing fix; a policy that cannot tell is unavailable.
- `prepare` takes one frozen copy of the request and its limits, and the time (the limits' `acceptedAt`, else now), before anything waits: every policy reads it and the making uses it, so neither a policy nor a caller changing its own objects meanwhile changes what is signed; that time is handed to the making (`askedAt`) as the token's `iat`, so the policies' wait moves it past no boundary.
- `prepare` answers the refusal `issue` would, or a frozen `PreparedAccess`, its header and claims texts as the token will carry them, signing nothing. `sign` signs only a value its own `prepare` answered, as made, again where asked; any other is the caller's TypeError.
- A token with less than a second left once signed, its end come, its cap passed, its lifetime spent in the policies' wait or its signing slow, is refused by `sign` as tokens' own rule: policy `tokens`, reason `no_lifetime_left`, the client's word `expired`, which `token-endpoint` answers `invalid_grant` whatever the grant. Any other answers its expires-in: what is left once signed, rounded up to whole seconds, at least 1.
- A token that would pass 16 KiB once signed, a fixed bound as Node's own 16 KiB header limit binds a bearer token sent to this provider, is refused by `prepare`, nothing signed, its signature counted at the length the signing key's makes, as `keys` prepares it: policy `tokens`, reason `token_too_large`, the client's word `too large`.
- The package warns of such a token as `tokens.token_too_large` with that length, the limit and the names of the claims a grant added, never a value. An actor chain over 16 is the caller's TypeError.
- An access token ends after its lifetime from its issue, capped at the expiry cap given. Its `iat` is the second of the limits' `acceptedAt` (when the issuance was accepted; a value not whole epoch ms is a RangeError), else of when `prepare` was asked, before the policies are; its lifetime runs from there. A grant tied to no session gives its standing time instead (`o3co_standing_at`, `standing`' card), which the subject check compares; a claim of another shape is `shape`.
- What a making keeps of a token (`MadeAccess`' `keep`) is kept only once the token is handed out, so one refused leaves no trace. tokens keeps nothing: a token is signed and handed back, no store, ledger or record written. The stand-in keeps what it issued.

## Depends on
- `added-claims` (the claims a grant adds, checked), `claims` (what a grant may say and add), `kernel` (freezing, unavailable), and the package's contract and limits.
