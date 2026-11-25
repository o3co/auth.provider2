# grant

Internal module of `refresh`: the `refresh_token` grant, and its revocation.

## Responsibilities
- Refreshes a live family for its own client and key, its root checked again (proposal 3.9), as one bundle rooted in the family; revokes a family by its token.

## Not here
- Founding a family (`family`). The rotation a refresh names, and whether the family is live on the flow (`token-endpoint` on the applied state).

## Offers
- `refreshGrant` (`GrantParts`: the records, `keys`' `verifyOf`, `webauthn`'s `reverifyAssertion`, `session`'s `entryOf`, `tokens`' `revokeReferenced`, `claims-selection`'s `forRefreshed`, the delegation's length, the clock) → the grant; `revocableFamilies` → the `refresh_token` revocable kind. `grantIn`, `grantTakes`: the same over the composition.

## Invariants
- A token is taken only where its family is live, its client's, its secret's hash the family's (compared in constant time) and the request's proof by the family's key (`sameBinding`).
- Its root is checked again, never the Store's word for it: the statement by the Core ring of the generation that signed it, of this client and the family's key; the assertion by the key the family recorded (`reverifyAssertion`, for the statement's challenge); the family's scope within the statement's, its audience the one resource the statement asked where it asked one; its end within the statement's issue and the delegation.
- Then its session enters, the policies admit it (`continuing`), and one bundle is issued, rooted in the family (`via` `refresh`), ending no later than the family or its session; a family not live on the flow's state is refused there, answered as every refused token.
- Its session is read again once the bundle is issued and its token recorded to it (proposal 3.15, 1): one closed meanwhile, whose close found no token to end, has that token revoked and none answered (unavailable where it cannot be revoked). Then its claims are kept for the token (`forRefreshed`), and the same refresh token is answered.
- No ID token is answered: a refresh's answer is not bound to the request (proposal 3.9).
- Revoking takes the family's own client's token alone (`written`); another client's is `done`, an unknown token `unknown`.

## Depends on
- `keys`, `webauthn`, `session`, `tokens` (revoking a token issued as its session closed), `claims-selection`, `sdk-core-wire` (the statement's schema, challenge input and `typ`), `sender-binding`, `token-revocation` (the kind's contract), `grants`, `clients`, `kernel`; the package's records and store.
