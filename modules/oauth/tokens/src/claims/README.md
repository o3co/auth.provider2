# claims

Internal module of `tokens`: the claims an access token carries, as tokens writes them.

## Responsibilities
- Holds the closed table of the claims tokens writes, and writes a grant as those claims.
- Holds the subject's kind a grant says, and what a grant may not add.

## Not here
- What each grant's tokens must hold beyond the table's names and default classes: the monitor's rules, as a refresh's `amr`, `acr` and `auth_time` matched with its root's, and no `o3co_standing_at` from a code's exchange.
- Signing the claims, their times and the binding (the package's), the standing time (`standing`). Reading them back (`verification`). The rules of an added claim (`added-claims`).

## Offers
- `accessTokenClaims`, the table the contract offers: each claim tokens writes by how it is held to account, `evidence`, `derived`, or `outside` the monitor's check, as `txr` is.
- `inTable` (a name) → whether tokens writes it, whether or not `added-claims` reserves it.
- `checkClaims` (a grant, the claims it adds) and `grantClaims` (a kept grant → its claims).

## Invariants
- A subject's kind is written as `o3co_subject_kind`: `user`, or `client` for a client's own token, whose subject is the client it is issued to. A grant saying neither, or a client's token for another subject, is the caller's TypeError.
- `o3co_subject_kind` is a provisional name: how a resource tells a client's subject from a person's is not settled, and the name follows it.
- A claim a grant adds takes no name of the table: the caller's TypeError, though `added-claims` may not reserve it.
- `act`, `amr`, `auth_time` (to the second) and `acr` are written only when the grant gives them; an empty `amr` counts as none, `auth_time` is never after `iat`, and none is written where the grant marks its authentication time unknown; an empty `acr` or an authentication time that is no number is the caller's mistake.

## Depends on
- The package's contract.
