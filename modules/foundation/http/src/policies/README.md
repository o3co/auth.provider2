# policies

Internal module of `http`: the policies routes use, the rules that apply them, and the marks that say what they keep.

## Responsibilities
- Names a policy, a route's use of one, a policy's rule, and a policy owner's mark, and the points the rules and the marks are contributed at.

## Not here
- What a policy decides and answers, and whether a mark is true (its owner's: a mark is its owner's claim, never a proof).
- Applying the rules to a route's requests (the server's), and checking routes against the marks (`guarantees`).

## Offers
- `policy` makes a policy, unique as a value, its label naming it only in a report; `use` is a route's use of one with its options, copied and frozen at boot.
- `policies`, `http.policies`: the rules (`PolicyRule`, made by `applying`), each passing the request on or answering it, matched to the policies routes use by value; a route's policies run in its order before its handler, and the first answer ends the request.
- `marks`, `http.marks`: one per guarantee (`RouteGuarantee`: `own-site`, no other site's request reaches the handler; `per-source`, a source over its count does not), each `PolicyMark` naming the policies that keep it for the methods named.

## Invariants
- A policy and a use of one are frozen values; a rule and a mark match a policy by value, never by label.

## Depends on
- `kernel` (its extension points).
