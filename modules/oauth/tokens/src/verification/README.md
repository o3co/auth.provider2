# verification

Internal module of `tokens`: reading an access token back, everything but revocation and the conditions.

## Responsibilities
- Verifies a token through `accessTokenSigning`, reads its claims by the table, and answers the access it grants or why it is invalid.

## Not here
- Revocation, access conditions and the subject check (the package's). Writing the claims (the package's), and their standing time (`standing`).

## Offers
- `checkingWith` (the signing, `sender-binding`'s token types, the issuer, the clock, `added-claims`' reading back) → a check of a token, given an allowance past its expiry: the access, with its issue time, or invalid with the reason.
- `compactLimit`: the longest compact token tokens issues or reads, 16 KiB.

## Invariants
- A token without `typ` or a subject kind, with several bindings, with a binding no kind of the composition writes, a client's naming another subject than its client, or one holding `txr`, which tokens never writes, is refused as `shape`.
- A token whose `exp` comes before its `iat`, whose `iat` is over 60 s ahead of the clock (hosts' clocks differ), or with over a day between them is none `tokens` issues: refused as `shape`.
- A member past the table is an added claim, copied by `added-claims`' reading back; one outside its rules is refused as `shape`. One read over 16 KiB is invalid, and an actor chain over 16 is not read.

## Depends on
- `added-claims`, `standing`, and the package's contract and limits.
