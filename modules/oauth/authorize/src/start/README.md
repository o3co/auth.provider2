# start

Internal module of `authorize`: the route of a login's start (②).

## Responsibilities
- Reads the screen's JSON, finds the client, takes the JAR (`jar`), checks the redirect URI and `prompt`, makes T's items, and under the JAR's reservation has `approvals` issue T, asking `withoutPasskey` whether the screen may offer `create()`; where it may and a sign-up is offered (`signUpOffers`), T allows its sign-up (F1).

## Not here
- The JAR's source, verification and reservation (`jar`).

## Offers
- `starting` (`StartParts`) → the handler; `startRoute` (the route's declaration); `byValue` (the `request` source); `filledItems` (the items it declares); `issuerMetadata`.

## Invariants
- The screen's keys are an uncompressed P-256 point (65 bytes, `0x04` first) and its signing key's x and y (32 bytes each), base64url; anything else is `invalid_request` before the client is looked up or the JAR reserved.
- `prompt` is no item of T: `none` is `login_required`, as every login asks the person's passkey; `login`, `consent` and `select_account` are met by that tap and dropped; any other word is refused. A JAR claim no item names is refused.
- Starts are counted per source by `rate-limit`'s policy; statements are counted by `approvals` per source key and in all. Its refusal `limited` is `rate_limited`, `items` is `invalid_request_object`, any other `temporarily_unavailable`; the same start may then try again.

## Depends on
- `clients` (`find`), `redirect-uris` (`redirects`, `matches`), `approvals` (`issue`), `sdk-core-wire` (`itemsFromJar`, `jarClaims`), `http` (the answer); the package's `jar` and `claims`.
