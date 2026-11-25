# code-needs

Internal module of `authorize`: what a code needs of an authorization's request and its client, checked at the start before T and again at the finish before the session opens.

## Responsibilities
- Tells whether a request meets what its code will need, so nothing a code needs fails once the person tapped: the client allowed the code grant, an S256 challenge's shape, a binding asked for ahead in its form, the resource within the client's audiences (at the start by the one rule for the audience asked), the scope within its allowance; an OpenID request only where an ID token is made.

## Not here
- How each refusal is answered: the start's (`invalid_request`, `invalid_target`, `invalid_request_object`, `invalid_scope`) and the finish's own. Boot's refusal of two rules for the audience asked: the module.

## Offers
- `codeNeedsOver` (`CodeNeedsParts`: the binding kinds, whether an ID token is made, the rule, the issuer) → `asksOpenid`, `openidUnmet`, `atStart` and `atFinish`, each unmet need answered by its word (`Unmet`).
  - `atStart`: the code grant, the resource by the rule, the challenge, the binding asked for ahead; never the scope (`StartUnmet`).
  - `atFinish`: the code grant, the challenge, the scope and audience allowed, the resource, the binding; else the scope, audience and binding. It reads no rule for the audience asked: the start read it.
- `codeNeedsIn` and `codeNeedsTakes` over the composition; `targetsIn`, the rules for the audience asked themselves (`grants`' `targetRules`), not the token endpoint's `targets`, so no endpoint need be composed.

## Invariants
- `atStart`, in order: the code grant, the resource, the challenge, the binding. `openidUnmet` is asked on its own, as the start orders it.
- At the finish, in order: the code grant, the challenge, the scope allowed (`allowedIssuance`), the resource within the client's audiences, the binding.
- A JAR's `resource` at the start is read by the one rule (resource-indicators') within the client's audiences: unless it answers that resource alone, it is unmet, with the rule's description; none composed leaves any `resource` unmet.

## Depends on
- `client-allowance` (`allowsGrant`, `allowsAudience`, `allowedIssuance`), `clients` (the client), `code-grant` (`codeGrantType`, `challengeShape`, `openid`, `issuesIdTokens`), `grants` (`targetRules`, `TargetRule`), `sender-binding` (`requestedOf`), `sdk-core-wire` (T's items); `kernel`.
