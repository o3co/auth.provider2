# start

Internal module of `authorize`: the route of a login's start (②).

## Responsibilities
- Reads the screen's JSON as `front-core-codec` reads `loginStart`, finds the client, takes the JAR (`jar`), checks the redirect URI and `prompt`, makes T's items, and under the JAR's reservation has `approvals` issue T, asking `withoutPasskey` whether the screen may offer `create()`; where it may and a sign-up is offered (`signUpOffers`), T allows its sign-up (F1).

## Not here
- The JAR's source, verification and reservation (`jar`). What a code needs of the request, and the resource's reading by its rule (`code-needs`).

## Offers
- `starting` (`StartParts`) → the handler; `startRoute` (the route's declaration); `startRouteIn` (the route, its parts taken from the composition, given the module's answer to a person with no passkey and whether a sign-up is offered) and `startTakes`; `byValue` (the `request` source); `takenOf` and `onlyOf` (the sources taken, and those saying they are the only one); `filledItems` (the items it declares); `issuerMetadata`; `unfilled` (the items every T carries that no module fills).

## Invariants
- A start whose fields `requestOf` refuses (`front-core-wire`'s `loginStart`: missing, repeated, sent as no text, of a size or characters the wire does not give, or bytes not in their one base64url text) is `invalid_request`, before the client is looked up, a source asked or the JAR reserved. Each field the sources are given is one the wire names, as the Front carries it: an empty one is not sent.
- The screen's encryption key is an uncompressed P-256 point (`0x04` first; its length the wire's); anything else is `invalid_request` before the client is looked up or the JAR reserved.
- A request source that says it is the `only` one taken is taken alone (`takenOf`): a start by value is then `invalid_request` ("a request by value is not taken"), and `request_parameter_supported`, read from the same sources taken, is `false`. Two such refuse boot.
- A start naming both a `request` and a `requestUri` is `invalid_request`, before a source is asked, whichever sources are composed.
- Under PAR, T's `request_uri` is the one its start named, as it came, resolving it its source's alone; a start by value carries none. A resend of the same JAR under the same screen keys, by another `request_uri` or, where it is taken, by value, is answered the T kept for the reservation, which names its own start's, so a screen holding another refuses it and the relying party starts again.
- `prompt` is no item of T: `none` is `login_required`, as every login asks the person's passkey; `login`, `consent` and `select_account` are met by that tap and dropped; any other word is refused. A JAR claim no item names is refused.
- Before T, in order: an OpenID request where no ID token is made, the `claims` read (`requestClaims`, any refused where no module reads them), then what a code needs (`code-needs`' `atStart`); a need unmet is `invalid_request` (the code grant), `invalid_target` (the resource, RFC 8707 §2, with the rule's description; so T never shows a resource its token would not carry), `invalid_request_object` (the challenge, the binding), `invalid_scope` (an OpenID request where no ID token is made).
- Starts are counted per source by `rate-limit`'s policy; statements are counted by `approvals` per source key and in all. Its refusal `limited` is `rate_limited`, `items` and `long` are `invalid_request_object`, any other `temporarily_unavailable`; the same start may then try again.
- A JAR's `claims` asking a claim by `null` (an ID token's or userinfo's request) goes into T as `{}`; one that is no JSON object (§5.5's own form), or holding any other null, is `invalid_request_object` (`item:claims`, `sdk-core-wire`'s), first among these checks, before T. The null rule alone is a deviation, where §5.5 has a member not understood ignored: T is signed whole and its signer writes no null.
- T is asked to fit the route's contract, `front-core-wire`: its `loginFinish` statement, and also its `continue` statement where T may continue to a sign-up (`fits`, the smaller).

## Depends on
- `clients` (`find`), `client-assertion` (the JAR's signature, through `jar`), `issuer` (its URL), `redirect-uris` (`redirects`, `matches`), `approvals` (`issue`), `sdk-core-wire` (`itemsFromJar`, `jarClaims`), `front-core-wire` (the statement's bound), `front-core-codec` (`requestOf`, `carriedOf`), `rate-limit` (its policy), `http` (the answer); the package's `jar`, `code-needs` and contract (`jarReservations`, `requestSources`, `requestClaims`).
