# audience

Internal module of `grants`: the rule for the audience a request asks for, as resource indicators (RFC 8707) contribute it.

## Responsibilities
- Defines the rule a request's audience is read by, the extension point it is contributed at, and the composed rule a grant (the root's `GrantInput.target`) or another endpoint asks.

## Not here
- The rule itself (`resource-indicators`); composing it at the token endpoint (`token-endpoint`, which provides `targets`); a client's ceiling (`client-allowance`).

## Offers
- `target`: the audience `targets` answers within the grant's ceiling.
- A grant that takes its audience from the request declares `targets`; any other is first asked the rule's `untargeted`, and its refusal is answered before the grant runs.
- Extension point `targetRules`: at most one rule; two refuse boot. A rule's `target` is given the request's parameters, the default audience and whether the issuance may have another; it answers the audience, or `invalid_target` with a description, which is the answer.
- A rule may answer `untargeted` (the request's parameters, for a grant or endpoint that takes no audience) and `repeated` (a parameter's name, sent more than once) with `invalid_target`, which is then the answer.
- `targets`: the composed rule, provided by `token-endpoint`. With none composed, the default audience, the request unread.

## Depends on
- `kernel`.
