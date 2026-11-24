# client-credentials

## Responsibilities
- Contributes the client credentials grant (RFC 6749 §4.4): a confidential client takes a token for itself, within its allowance.

## Not here
- Authenticating the client, the endpoint and its answers, and the bundle a token is issued in, recorded on the client's own flow (`token-endpoint`). What a client may be issued (`client-allowance`). Issuing the token (`tokens`, through `grants`' `issue`). Which keys are the client's (`client-assertion`).

## Offers
- Contribution to `grants`: `client_credentials` (`clientCredentialsGrantType`), reading no ambient credential, taking its audience from the request.
- `clientCredentials` (issuer, `client-assertion`'s `verifiedOf`) → the grant, for an assembly of one's own.

## Invariants
- Only a confidential client is served; a public one is `unauthorized_client`.
- The scope is the client's defaults when it asks none, never one outside its allowance (`invalid_scope`); the audience is within its allowed audiences, or the issuer when it has none.
- The token's subject and the client it is issued to are both the client, its subject's kind `client`; it is one bundle, naming no root, as the client's registry version is on no log here. Nothing is used up before issuing.
- A token bound by DPoP is issued only where the proof's key is the key the client's assertion was verified with, of the registry version the client came from (`client-assertion`'s `verifiedOf` of what the client's authentication verified, `authenticated`, for this client): its `cnf` is that key's thumbprint, so using it needs the client's private key.
  - Otherwise, a client that authenticated by no assertion included, `invalid_dpop_proof`, nothing issued. A binding of another kind, or none, is left as it is.

## Depends on
- `grants`, `client-allowance`, `client-assertion`, `issuer` (its URL), `kernel`
