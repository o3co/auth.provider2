# issuance

Internal module of `token-endpoint`: what a grant issues through for one request, the `admits` and `issue` it is handed, over an `Issuing`.

## Responsibilities
- Builds a grant's `admits` and `issue` over an `Issuing` (the endpoint's runs bundles, the test caller's signs at once), with the request's binding, telling the session issuances of a token issued from a session.
- A request issues one bundle: a second `issue` is the grant's maker's mistake (a TypeError, `500`), none of it answered.
- A token whose subject's kind is not the one its grant declares (`declared`, `issuanceFor`'s last argument) is the grant's fault too: a TypeError before anything is issued.

## Not here
- Running a bundle on the flow, its tokens signed and taken in (`bundle`). The request, the checks before the grant and the answer, applying `answeredIssued` (`route`; `caller` in its tests).

## Offers
- `Issuing`, how a grant's `issue` issues: the endpoint's runs a bundle (`endpoint-in`, over `bundle`), the test caller's signs at once (`caller`).
- `issuanceFor` (an `Issuing`, grant type, binding, session issuances, a bundle, `bundleOf`) → a grant's `admits` and `issue`, which notes in the bundle each token's subject and its kind as handed to `tokens`, the token, and the added claims' names `tokens` answers, never the grant read again; `answeredIssued` (a bundle, grant type, an answer's body) throws for an `access_token` it does not hold; `refusedAnswer`, the one answer to a refused issuance.

## Depends on
- `grants` (the input's `admits` and `issue`, bundle parts and rooting, the refusal, session issuances), `sender-binding` (the binding type), `tokens` (the issuance request and its answer, `referenceOf`).
