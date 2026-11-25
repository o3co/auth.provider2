# client-allowance

## Responsibilities
- Decides what a client may be issued and may see: its grants, scopes and audiences; owns the client metadata section that holds them.

## Not here
- How a refusal is answered (`unauthorized_client`, `invalid_scope`, `invalid_target`): each caller's.
- The audience a request asks for within what is allowed: `token-endpoint`'s target rule.
- Where a client's record comes from: `clients` and its sources.

## Offers
- `clientAllowance`, decisions over a client's section:
  - `allowsGrant`: a grant is allowed only when its allowed grants list it; `grantsOf` answers that list, as a boot check that compares it with the grants composed reads it.
  - `allowsScope`: one scope is allowed only when its allowed scopes list it.
  - `allowedIssuance`: the scope and audience for a requested scope. No scope asked gives the defaults; an explicit empty default gives no scope, and no default at all is refused while scopes are allowed. A scope outside the allowed ones is refused. The audience is the first allowed one, else the issuer.
  - `covers`: an earlier issuance (`Issued`) has every scope allowed, and exactly one audience the client may be issued.
  - `allowsAudience`: any allowed audience, or the issuer when none is allowed.
  - `maySee`: the audience includes an allowed audience or the client's own id.
  - `parseScope`: RFC 6749 scope tokens joined by single spaces; an empty value names none, as when left out.
  - `allowedIssuanceWithin` and `allowsAudienceWithin`: the same within ceilings (`Ceiling`, a `scopes` and an `audiences` list, each optional). Each list a ceiling holds narrows the client's, its defaults and the issuer's audience among them, and an empty one allows nothing; a default narrowed to none is refused, and no audience left is `invalid_target`.
  - `selfAudiences`: the audiences of the client's own ceiling, in its order; none for a client not of a signed version.
  - `allowedSelfIssuance` (client, requested scope, audience asked, issuer): what a client may be issued for itself, by its own ceiling alone. A client not of a signed version, or whose ceiling names the issuer, is `unauthorized_client`. The scope is named, with no default (`invalid_scope`); one audience, named unless the ceiling holds one entry (`invalid_target`); every scope within that audience's entry (`invalid_scope`).
  - `allowancesWithin`: the section entry for a client asking within a ceiling. Each list keeps what both hold, and a list not asked is the ceiling's. Refused when the asked audiences leave none of a ceiling that names some, since none means the issuer.
- `AllowanceLists`: the grants, scopes and audiences lists a ceiling and a request name.
- Client metadata section `client-allowance`: `grants`, `scopes`, `audiences` (default empty, allowing nothing), `default-scopes` (unwritten means "not set", which differs from an explicit empty value), `self` (the client's own ceiling: entries of `audience` and `scopes`, default empty). Readers do not interpret the values themselves; they use `clientAllowance`.
- For tests (`./testing`): `allowancesFor`, a test client's sections holding the given allowances.

## Invariants
- A client without the section is allowed nothing; an unknown field in it refuses the client's record.
- OpenID Connect's offline access is not offered (out of scope): `offline_access` in `scopes` or `default-scopes` refuses the client's record at that entry.
- Decisions are pure: no failure, no state. `allowancesWithin` never widens the ceiling.
- The client's own ceiling is apart from the person's delegation: `allowedSelfIssuance` reads `self` alone, and the other decisions never read it. It is read only for a client whose source declares it signed (`clients`' `signed`), never from the client's version alone, so a registered client is issued nothing for itself.
- An audience written in two entries of `self`, or `offline_access` or `openid` among an entry's scopes, refuses the client's record at that entry. `openid` is refused there because a client's own token carries no person. A registered client writing a non-empty `self` refuses boot, as no one would read it; one of those entries refuses it at that entry.

## Data
- None, so it is safe on many instances.

## Depends on
- `kernel`, `clients`

## Vocabulary
- allowance: what a client may be issued: grants, scopes and audiences. ceiling: the most a client from a source may be allowed.
- self ceiling (`self`): what a client may be issued for itself, apart from what a person delegates: audience and scope pairs its publisher signed.
