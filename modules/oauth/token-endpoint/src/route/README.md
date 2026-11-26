# route

Internal module of `token-endpoint`: the handler of `POST /oauth/token`, from the request to the answer, and what a grant issues through.

## Responsibilities
- Hands a grant what its client's authentication verified (`authenticated`), unread; none for a client a grant identified.
- A request issues one bundle: a second `issue` is the grant's maker's mistake (a TypeError, `500`), none of it answered; so is an answer whose `access_token` is not one its `issue` gave, so an answer carries the very token its checked bundle holds. Its evidence is what was verified: the binding read, and the client's assertion where its authentication is marked `assertion`, never for another method's `proof`; with the client's registry version, where it has one.
- Reads a request's grant type and parameters, authenticates the client, or has a grant identify the client of a request naming none, checks the grant is allowed it and the binding, hands the grant its input, and answers what it gives, as the package's card says.
- Builds a grant's `admits` and `issue` over an `Issuing` (the endpoint's runs bundles, the test caller's signs at once), with the request's binding, telling the session issuances of a token issued from a session.

## Not here
- The composed rule for the audience (`built-in`). Authenticating the client and the shapes of an error answer (`answers`). Taking the contracts below from the assembly (`endpoint-in`). The route's declaration, its limit and the metadata items (the package's module).

## Offers
- `tokenEndpoint` (its parts: clients, the request's `Issuing`, issuance fencing, session issuances, binding readers, required bindings, grants by type, the audience rule, audit) → the handler and its answer to Unavailable; `tokenPath`.
- `grantInputOf` (what a grant is handed: its parameters' reader, the audience rule, `admits` and `issue`), `readerOf` and `mistypedRefusal`, which the internal module `caller` uses too.
- `issuanceFor` (an `Issuing`, grant type, binding, session issuances, a bundle, `bundleOf`) → a grant's `admits` and `issue`, which notes in the bundle each token's subject and its kind as handed to `tokens`, the token, and the added claims' names `tokens` answers, never the grant read again; `answeredIssued` (a bundle, grant type, an answer's body) throws for an `access_token` it does not hold; `refusedAnswer`, the one answer to a refused issuance.
- `answeredBody` (a grant's issued body as answered).
- A refused authentication is answered as `authenticateClient` answers it (`refusedAuthenticationAnswer`, the one mapping), and recorded only where no grant identifies the client.

## Invariants
- Records each answer but an unavailable one through the package's declared audit events, once the client is authenticated, or once a request goes to a grant that identifies its client (with `identified`, and `client` once known).
- `token.issued` adds `version`, the client's registry version, and `binding` and `confirmation`, the tokens' `cnf` member and value, where there are; and `claims`, the names of the claims a grant added, never their values, as many as fit 2048 characters, with `claims_left` past that.
- The failure's `reason`: `client_not_identified`, `repeated_parameter`, `mistyped_parameter`, `authorization_details`, `missing_grant_type`, `unsupported_grant_type`, `grant_type_not_allowed`, `unsupported_body`, `multiple_bindings`, `binding_refused`, `binding_required`, `binding_kind_not_named`, `untargeted`, `grant_refused`, `issuance_refused` with `policy` and `refusal`, or `issuance_fenced` with `fence`.
- A request carrying `authorization_details`, on any grant, in a form or in JSON (of any type but `null`, as if left out), empty or not, is refused after the client's authentication (its assertion spent) and the mistyped parameters, before `grant_type`: `invalid_request`, "authorization_details are not taken", as PAR refuses it (A25: rich authorization requests are not taken; `refusals` has no word of their own). Through a Front it arrives as sent or not, an empty one as not sent.
- A request naming no client, sent to a grant that identifies its client, is recorded with `identified` (`grant`) from the first check on, its `client` once the grant identifies it; its authentication's refusal is not recorded.
- A grant type nothing dispatches to is `unsupported_grant_type`, and is never named in the audit or the log.

## Depends on
- `audit`, `client-allowance`, `clients`, `grants`, `http`, `request-source`, `sender-binding`, `tokens`; the package's contract and audit events; `answers` (client authentication, error answers and challenges); `identified` (the client a grant identifies).
