# bundle

Internal module of `token-endpoint`: the issuance bundle (A40), its owner's run of it over `transparency`, from the policies' judgment to its tokens signed and taken in.

## Responsibilities
- Runs one bundle a grant's `issue` asks: the policies judge it, its start is recorded with the request's evidence, its access token prepared with the start's acceptance time as its `iat`, the bundle appended once, signed after its receipts, and answered once taken in as its owner's `took`.

## Not here
- What a grant issues, the binding, the session issuances and the fences (`route`). Frames, leases, the end of an op and abandonment records (`transparency`). The token's texts and signing (`tokens`).

## Offers
- `bundleKind`: the kind of operation `token-endpoint.bundle`, a bundle (never taken over), holding no records of its own.
- `bundling` (`BundleParts`: `transparency`, the log's digest, tokens' `admits`, `prepare` and `sign`, a fresh ground, the pause and number of looks at the judgment) → the run of one `BundleAsk` (the request and limits, the evidence, its root's reference) → `tokens`' answer.
- `evidenceOf` (a request, what was verified) → its DPoP proof where the token is bound by DPoP, and its client assertion where the client's authentication verified that assertion (`clients`' `assertion` mark); `flowOf` (a grant) → its subject's flow, a person's or the client's own.

## Invariants
- An op's id is the digest of the evidence verified; with none, of a fresh ground. Its digest is its start's plaintext digest.
- A refusal of the policies records nothing. A refusal or a failure once its start is recorded closes the op without its bundle on a client's flow; nothing is signed.
- On a subject's flow, closing (`rebase`) answers `notReady` until the flow is taken in to its head, and a second stage refused `prevMismatch` is answered unavailable, not rebased: neither closes nor resends there, and the op is abandoned once its lease ends, the flow held until then.
- A refused or lost append of the bundle signs nothing. Signing that falls after the receipts appends the same bundle again, the same id and bytes, and signs again, once.
- A refusal of the signing after the receipts hands nothing out; the bundle, left alone, is abandoned by a replica tending its flow. A replica that falls is never taken over: the request fails.
- Only the owner's `took` answers the token; a bundle held, not taken, or not judged after its looks answers unavailable.
- The start's content is empty, and a client's root is named only where the client's registry version is on the log.

## Depends on
- `transparency` (the contract, the kind's shape), `transparency-wire` (a token's digest input, the preimage's evidence), `tokens` (prepare, sign), `http` (the request), `sender-binding` (the binding), `kernel` (unavailable).
