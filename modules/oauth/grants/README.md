# grants

## Responsibilities
- Owns the grant extension point: what a grant is given, and how its answer is answered.
- Owns the rule for the audience a request asks for, as resource indicators (RFC 8707) contribute it.
- Defines the contract for the grant types composed (`composedGrants`).

## Not here
- Each grant's own decisions (the contributing side owns them). The token format (`tokens`).
- The token endpoint, its checks before a grant runs, and its audit (`token-endpoint`, which keeps this contract).
- What a grant listed in `grantServers` does: the index holds its grant type and module as words alone, never its contract.

## Offers
- Extension point `grants`: grant type → handler, one for each grant type (two refuse boot).
- A grant runs only for a client it is allowed to, once the request's binding is read: one that authenticated, or one the grant identified itself.
- A grant may `identify` the client of a request that names none and carries nothing a client authenticates with: the client its own credential identifies, which must be one registered with no credentials (public, method `none`), or its refusal. It then runs for that client as for an authenticated one, given back what it identified (`identified`) unread. A grant without `identify` never sees such a request.
- A grant names the bodies it takes (a form when it names none). It reads a parameter as one string, or as sent (a JSON member of any type); a repeated parameter, or an OAuth parameter sent in JSON as neither a string nor `null`, never reaches it.
- A grant's refusal is an OAuth error code (`OAuthError`) or one the grant owns, answered `400`, `401` for `invalid_client` or when the grant names it, or `429` (too many requests) when it names it, with its wait (`retryAfterMs`) as `retry-after` in whole seconds; any other status is ignored.
- A grant's `401` carries the `WWW-Authenticate` challenge of the client's authentication method, or every method's when it declares none; a grant sets no header.
- Other members of a grant's refusal pass through unread, but a member named as in the error or a success answer is dropped, and so is an `error_uri` that is not a URI of printable characters.
- A grant is given the request sender's binding, and what its client's authentication verified (`authenticated`, the method's owner reading it), unread.
- A grant says whom it issues for in what it gives `admits` and `issue`: the subject, and the subject's kind (`tokens`' `subjectKind`), `user` for a person, or `client` where the client gets a token for itself, as the client credentials grant does, its subject then the client. A grant may declare that kind for every token it issues (`subjectKind`), a declaration the token endpoint reads, never a proof.
- `admits`: whether `tokens`' issuance policies allow a grant now, under the grant type, the session it comes from and `tokens`' `continuing`.
- A grant declares `readsAmbient`: `cookie` when it reads the session's cookie, which a browser sends by itself, and then checks the request's origin itself; `none` otherwise. The token endpoint's route has no own-site policy and relies on it; it is a declaration, never a proof.
- `issue` (internal module `issuance`): one bundle, `BundleRequest` with its `parts` (`BundlePart`, `BundlePlaced`) and how a person's roots (`Rooting`), answered issued, or `Refused` (`400 invalid_grant`); extension point `sessionIssuances`, told of each token issued from a session.
- The audience asked (internal module `audience`): a grant's `target` and its declaration `targets` (`Grant`); extension point `targetRules` (at most one), `TargetRule`, `TargetRequest`, `TargetVerdict`, and `targets`, the composed rule `token-endpoint` provides.
- Every credential an `issued` answer carries, additions included, is for the one subject its `issue` issued under: an answer issued under none or more than one is the grant's fault, `500`, none of it answered. Before it goes out, that subject passes `tokens`' issuance fences; a bundle refused is answered as a refused issuance, with `tokens`' description.
- `composedGrants`: the grant types composed, answered by `token-endpoint`'s module.
- `grantServers`: the index of first-party grants, each grant type by the module that serves it, as that module's manifest declares (`grantTypes`); a test holds the two alike. A type it does not list, a name every object has included, answers none.

## Depends on
- `kernel`, `http`, `clients`, `sender-binding`, `tokens`

## Vocabulary
- grant: a procedure that issues tokens, chosen by grant type name.
