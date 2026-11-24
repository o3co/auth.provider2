# bundle

Internal module of `token-endpoint`: the issuance bundle (A40), its owner's run of it over `transparency`, from the policies' judgment to its tokens signed and taken in.

## Responsibilities
- Runs one bundle a grant's `issue` asks: the policies judge it, its start is recorded with the request's evidence, its access token and parts prepared with the start's acceptance time as their `iat`, the bundle appended once, each token signed after its receipts, and answered once taken in as its owner's `took`.

## Not here
- What a grant issues, the binding, the session issuances and the fences (`route`). Frames, leases, the end of an op and abandonment records (`transparency`). The token's texts and signing (`tokens`).

## Offers
- `bundleKind`: the kind of operation `token-endpoint.bundle`, a bundle (never taken over), holding no records of its own.
- `bundling` (`BundleParts`: `transparency`, the log's digest, tokens' `admits`, `prepare` and `sign`, a fresh ground, the pause and number of looks at the judgment) → the run of one `BundleAsk` (the request and limits, the evidence, its root's reference and how a person's roots there, the client's registry version, its parts) → `tokens`' answer, with each part's token in the order asked.
- `evidenceOf` (a request, what was verified) → its DPoP proof where the token is bound by DPoP, and its client assertion where the client's authentication verified that assertion (`clients`' `assertion` mark); `flowOf` (a grant) → its subject's flow, a person's or the client's own.

## Invariants
- A person's op's id is the digest of the evidence verified; with none, of a fresh ground. A client's op's is `authority-rules`' `tokenRules.client.start` of its evidence, one client assertion and one DPoP proof of a client of a registry version (else refused before it is decided, `evidence`), its start naming their elements and the client's registry version; never a fresh ground. Its digest is its start's plaintext digest.
- A client's start and bundle say they root in the client (`via` `client`); its bundle carries its token's header and claims texts. Its start refused `evidenceUsed` is refused for good (`evidence_used`, `invalid_grant`). Its bundle is sent only where its evidence's times hold its start's acceptance within 5m (`tokenRules.client.within`; the rules' window is wider), else the op is closed without it and the request unavailable (KE-C02).
- A refusal of the policies records nothing. A refusal of its bundle's making once its start is recorded closes the op without its bundle; on a client's flow, a refusal of an append leaves the op to its lease's end (but `abandoned`, which closes it); nothing is signed.
- On a subject's flow, closing (`rebase`) answers `notReady` until the flow is taken in to its head, and a second stage refused `prevMismatch` is answered unavailable, not rebased: neither closes nor resends there, and the op is abandoned once its lease ends, the flow held until then.
- A refused or lost append of the bundle signs nothing. Signing that falls after the receipts, the access token's or a part's, appends the same bundle again, the same id and bytes, its receipts held to the same count, and signs every token again with its own, once, each signing settled first.
- A refusal of the signing after the receipts hands nothing out; the bundle, left alone, is abandoned by a replica tending its flow. A replica that falls is never taken over: the request fails.
- Only the owner's `took` answers the token; a bundle held, not taken, or not judged after its looks answers unavailable.
- A person's start names its root as its parent, where it has one, and its content says how it roots there (`via` `code`, or `refresh` with its rotation), its bundle's content the same; none given, empty.
- Its op is decided with what its bundle changes, as `authority-rules`' `effectOf` reads the bundle: by a code, a family of its approval and the code's use-once mark; by a refresh, its family rotated; a client's, or one with no root, nothing. They are taken in with the bundle, its start changing nothing (`transparency`).
- Each part is prepared before the bundle is sent, its digest recorded after the access token's in the order asked; a part that fails to prepare closes the op. Each is signed only after the receipts, with its own: one per token in order, the access token's first. A log that answers another number signs nothing, unavailable.

## Depends on
- `authority-rules` (`tokenRules.client`), `transparency` (the contract, the kind's shape), `transparency-wire` (a token's digest input, the preimage's evidence), `tokens` (prepare, sign), `http` (the request), `sender-binding` (the binding), `kernel` (unavailable).
