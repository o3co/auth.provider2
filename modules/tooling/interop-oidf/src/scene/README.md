# scene

Internal module of `interop-oidf`: the provider as the OIDF run meets it, for its tests alone.

## Responsibilities
- Runs the generated `nextgen-core` (with `sign-up` added) and `nextgen-front` as their operators run them, each in a process of its own (`create-app`'s `./testing`), the Core over fakes of KMS (its wire's fake), SMTP and a signed client registry, on Redis as generated where the harness runs one, else the memory store.
- Writes what the operator publishes by the Core app's own entries (`discovery-publish`, `keys-publish`), and answers it at the issuer's origin as the publisher would.
- Puts an https front (`conformance-front`) at the issuer's origin, the deployment's edge (TLS 1.2 at least, by BCP 195's suites alone): the published files answered there as `publish-serve` answers them, the screen's pages their reader, everything else passed to the Front, which reaches the Core over the wire.

## Not here
- The suite, the screen, the relying party and the resource: the package's other internal modules.
- The configuration of each module: each module's configuration builder, which the scene composes.

## Offers
- `startScene` (`SceneSpec`: the host the front is named by and the address it listens on, as `hostForSuite` gives them; the screen's origin; the registry's clients; PAR's `jar-max-lifetime` where a run sets one; `byValue`, a login's start taking a JAR by value too, for a test of the words only that start answers; `redis`, the server the harness runs) → `Scene`: the issuer's origin, the certificate its front answers with, every app's output so far, and its stop.
  - Its output: `output`, every app's as one text, for a failure to show; `outputs`, each app's by its name, kept past the stop.
- `differencesOf` (a spec) → the pattern's differences in it, each a line of a run's report; `storeOf` → the store's axis and section.
- `sender`: the one address the apps are told of for every request. `ask` (an `At`: an origin, the one certificate trusted there, and the address its host is reached at where this machine has no name for it), failed past its whole time or where its answer is cut off → a request's answer (a form or JSON); `atIssuer`, a scene's issuer as an `At`.

## Invariants
- The pattern's differences are these alone, each named for a run's report (`differencesOf`): the spec's, `sign-up` added, the store, one sender (RFC 5737's `192.0.2.10`: every client reaches the front from loopback, which the Front takes for its trusted proxy), and the harness answering the published files (the publisher is the operator's and trusted).
  - The store: Redis with the operator's two statements (`replication`, `authentication`: `none`) and no `store.accept-*`; else the memory store, `accept-volatile` and `accept-unauthenticated` (redis's fake boots the module and serves no request).
- A process takes the environment `create-app`'s `./testing` builds whole, its configuration split as an operator writes it (`asOperator`), the Core's KMS endpoint and no credential or file of the account's besides.
- nextgen-core and nextgen-front run by their manifest's `start`, held by the permission model as `APP_PERMISSION` says (unset: audit), their output kept; the publish runs by their files, unheld.
- A stop tries every part, the last started first, though one fails (`lifecycle`'s `stopAll`), and tells every failure; a start that fails stops what it started and throws its own failure, the stop's beside it.
- Its files are tests' (`test/`).

## Depends on
- `lifecycle` (`stopAll`); `create-app` (`./testing`), `conformance-front`, and each composed module's configuration builder (its `./testing`; `kernel`'s from its contract).
