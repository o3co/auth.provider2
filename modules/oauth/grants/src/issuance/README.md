# issuance

Internal module of `grants`: one bundle a grant issues, its parts beside its access token, and who is told of a token issued from a session.

## Responsibilities
- Defines what a grant gives the root's `GrantInput.issue` and what it is answered: the bundle, how a person's roots on the log, the parts its owners make beside the access token, a refused issuance; and the extension point told of each token issued from a session.

## Not here
- Recording the bundle on the log, its receipts and its judgment (`token-endpoint`); the token's format and issuance policies (`tokens`); each part's making (`oidc`'s ID token, `refresh`'s family), and when one is asked (`code-grant`).

## Offers
- `issue`: asks again, then issues one bundle (`BundleRequest`: an access token, and the `parts` its owners make beside it, `idToken` or `family`, each prepared before and signed after the receipts with the bundle's record, `commit`ted once it is taken in, answered as `parts`; omitted `family` parts are `undefined` in place) with the binding, and the expiry cap and lifetime the grant gives. A grant may add claims (`AccessGrant.claims`, under `added-claims`' rules).
  - The bundle names its root's reference, where its root is on the log, and for a person's how it roots there (`Rooting`: by an approval's code, with the code's digest, or a family's refresh, its rotation read from the flow's state). Its start is recorded, its tokens made with that record's acceptance time as their issue time, recorded once before any is signed, and answered once judged: the token endpoint's.
- A refused issuance is a value the grant returns unread; it is answered for every grant as `400 invalid_grant` with the policy's description.
- Extension point `sessionIssuances`: told the session and the token's id and expiry by `issue` given a session. One failing revokes the token, and `issue` throws it on.

## Depends on
- `kernel`, `tokens` (`AccessGrant`, `IssuanceRefused`, `IssuedAccess`).
