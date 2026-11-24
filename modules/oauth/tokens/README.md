# tokens

## Responsibilities
- Owns the access token: its format and the closed table of the claims it writes, issuance, verification and revocation; stamps and checks `issuer`'s URL as `iss`.
- Revokes through `token-denylist`'s denylist, over the store interface it offers and `tokens` passes on.
- Its internal module `issuance` holds how `admits`, `prepare` and `issue` judge a request, and how `prepare` and `sign` make a token over the judgment; `standing`, a token's standing time as its claim writes and reads it; `claims`, the claims tokens writes; `verification`, reading a token back.

## Not here
- The procedures that lead to issuance, authenticating the requester, and other token kinds. The bundle a token is issued in and its record: the token endpoint's.
- Binding kinds and a holder's proof: `sender-binding`'s.

## Offers
- Issuance only through `issue`, or its two halves `prepare` then `sign`, policies first: `issue(request: grant, grant type, session, `continuing` (set by an issuing side whose grant the policies already let through); limits)` → issued, or refused by the first policy to refuse. `prepare` and `sign` are `issuance`' card's.
- What it issues for: a grant (subject, its kind, issued-to, audience, scope; optionally an actor chain, `amr`, an authentication time, `acr`, a standing time and the `claims` it adds), an expiry cap, a binding, and a lifetime other than the section's (`lifetimeSecondsRange`: 2–86400 s) → the token, its id, expiry, token type and the added claims' names.
- `SubjectKind`, the subject's kind a grant says, and `accessTokenClaims`, the closed table of the claims tokens writes, each by its `ClaimClass`; any other member is a claim a grant adds (internal module `claims`).
- Verification → the id, the grant (its added claims frozen), the standing time (its standing claim, else its issue), the token type (Bearer, or the bound kind's) and the binding; the validity check `sender-binding` admits a request at a resource by. What it refuses as `shape` is `verification`'s card's.
- Issued-to, for the revoking side to check the owner: answered for revoked tokens and within the allowance past expiry too; never for authorization.
- Revocation, directly or by a reference to an issued token (its shape is `tokens`' own), within the allowance past expiry; or unsupported, which `revocable` tells and every start warns of (`tokens.revocation_unsupported`). Whether subjects are checked, which `subjectsChecked` tells: false only where the section states `subject-check = none`, which every start warns of (`tokens.subjects_unchecked`).
- Extension points: issuance policies (request → allowed / refused with an audit reason and a client description); access conditions, and exactly one subject check (token id, subject and its kind, issue time, standing time → holds / revoked; unavailable when unknown); a revoked answer fails the token as revoked. Issuance fences, passed by `issuanceFencing.pass` (internal module `fencing`).
- `token-denylist`'s store interface for revoked tokens and its needs, passed on: a store wiring wires `tokens` and implements it.
- `jwks_uri` among `issuer`'s metadata: `jwks.json`, the key set `keys-publish` writes, under the issuer's URL, on its static origin and never the Front's. For an issuer with a path, it is under that path, as the discovery document's OpenID Connect place is: `keys-publish` writes into that path of the publisher's directory.
- Two handles. `accessTokenIssuance` (`AccessTokenIssuance`: `admits`, `prepare`, `sign`, `issue` and `accessTokenLifetimeSeconds`, `issuance`' card's) is taken only by a module that declares where it stands on the promises (`takersContribute`, `promises`' `stances`); one declaring nothing refuses boot. `accessTokens` (`Tokens`) is taken by any.
- Its own stance, as `accessTokenSigning` asks of its taker: it breaks `core-compromise-contained`, as an access token carries no receipt of the transparency log.
- Operator section: `access-token-lifetime` (written with its unit, `2s` to `1d` in whole seconds, default `5m`, counted from when `issue` is asked, the policies' wait included; a token it leaves less than a second once signed is refused, as `issuance`' card says).
- Operator section, beside it: `revocation` (`denylist` or `unsupported`), `issuance-timeout` (written with its unit, `1s` to `1m`, default `10s`), `subject-check` (`none` states that no module checks subjects), `added-claims` (`added-claims`' limits, each raised only).
- `./testing`: the contract test every implementation passes, configuration builders, and a stand-in: in memory, unsigned, ending and reading bindings as `tokens` does.

## Invariants
- Signed and verified through `keys`' `accessTokenSigning` alone; a signing its holder withdraws is unavailable.
- With no subject check, the section states `subject-check` `none`; with one, it does not; boot is refused otherwise. Under `none`, a revoked subject's boundary stops no access token: one lives until its expiry unless revoked another way, such as closing its session.
- Unavailable keys, store or checks answer unavailable, never a negative verdict.
- Added claims are the grant's statement: signed with the rest, a resource cannot tell them from the provider's, so composing a grant trusts it with its tokens' content.
- An added claim follows `added-claims`' rules, its shape, reserved names and limits, and `claims`'; one outside them is the grant's maker's mistake (TypeError at `issue`, `prepare` and `admits`, a 500 with no audit).
- An access token's `iat`, its end, what is left of it, and its refusal and warning past 16 KiB once signed are `issuance`' card's; its standing time, `standing`'s.

## Depends on
- `kernel`, `keys`, `issuer`, `sender-binding`, `added-claims`, `token-denylist`, `promises`

## Vocabulary
- scope / audience: the range of permission a token grants, and the token's recipient.
- issued-to: the identifier of whoever received the token; its contents are not interpreted.
- actor: who acts for the subject, as a chain (`act`).
- subject kind: whether the subject is a person (`user`) or the client itself (`client`).
- claim table: the claims tokens writes, each held to account as evidence, derived or outside the monitor.
