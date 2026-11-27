# start

Internal module of `authorize`: the route of a login's start (②).

## Responsibilities
- Reads the screen's JSON as `front-core-codec` reads `loginStart`, finds the client, takes the JAR (`jar`), has its request checked (`authorizationRequests`, internal module `request`), and under the JAR's reservation has `approvals` issue T, asking `withoutPasskey` whether the screen may offer `create()`; where it may and a sign-up is offered (`signUpOffers`), T allows its sign-up (F1).

## Not here
- The JAR's source, verification and reservation (`jar`). The request's check: the redirect URI, `prompt`, T's items, the `claims`, what a code needs (`request`).

## Offers
- `starting` (`StartParts`) → the handler; `startRoute` (the route's declaration); `startRouteIn` (the route, its parts taken from the composition, given the module's answer to a person with no passkey and whether a sign-up is offered) and `startTakes`; `byValue` (the `request` source); `takenOf` and `onlyOf` (the sources taken, and those saying they are the only one); `filledItems` (the items it declares); `unfilled` (the items every T carries that no module fills).
- `issuerMetadata`: what `authorize` publishes at the issuer's metadata but the authorization endpoint: `response_types_supported` (`code`), `response_modes_supported` (`form_post`), `code_challenge_methods_supported` (`S256`), `require_signed_request_object`, `request_parameter_supported`, `request_uri_parameter_supported`, `authorization_response_iss_parameter_supported`.

## Invariants
- A start whose fields `requestOf` refuses (`front-core-wire`'s `loginStart`: missing, repeated, sent as no text, of a size or characters the wire does not give, or bytes not in their one base64url text) is `invalid_request`, before the client is looked up, a source asked or the JAR reserved. Each field the sources are given is one the wire names, as the Front carries it: an empty one is not sent.
- The screen's encryption key is an uncompressed P-256 point (`0x04` first; its length the wire's); anything else is `invalid_request` before the client is looked up or the JAR reserved.
- A request source that says it is the `only` one taken is taken alone (`takenOf`): a start by value is then `invalid_request` ("a request by value is not taken"), and `request_parameter_supported`, read from the same sources taken, is `false`; `request_uri_parameter_supported` is whether a source taken `readsRequestUri`. Two such refuse boot.
- A start naming both a `request` and a `requestUri` is `invalid_request`, before a source is asked, whichever sources are composed.
- The request is checked (`request`) after the JAR is taken and before anything is reserved or signed; its refusal is answered as given, `400`.
- Under PAR, T's `request_uri` is the one its start named, as it came, given to the check; resolving it is its source's alone; a start by value carries none. A resend of the same JAR under the same screen keys, by another `request_uri` or, where it is taken, by value, is answered the T kept for the reservation, which names its own start's, so a screen holding another refuses it and the relying party starts again.
- Starts are counted per source by `rate-limit`'s policy; statements are counted by `approvals` per source key and in all. Its refusal `limited` is `rate_limited`, `items` and `long` are `invalid_request_object`, any other `temporarily_unavailable`; the same start may then try again.
- T is asked to fit the route's contract, `front-core-wire`: its `loginFinish` statement, and also its `continue` statement where T may continue to a sign-up (`fits`, the smaller). Under PAR it is the one refusal of the request left past the push: T's length is `approvals`' to tell, so a pushed JAR whose T outgrows its route is taken at `par` and refused here.

## Depends on
- `clients` (`find`), `client-assertion` (the JAR's signature, through `jar`), `issuer` (its URL), `approvals` (`issue`), `sdk-core-wire` (`jarClaims`), `front-core-wire` (the statement's bound), `front-core-codec` (`requestOf`, `carriedOf`), `rate-limit` (its policy), `http` (the answer); the package's `jar` and contract (`jarReservations`, `requestSources`, `authorizationRequests`).
