# interop-oidf

## Responsibilities
- The ledger of the provider's intended deviations and strict choices (L1), `docs/compliance/deviations.json`, which a conformance run's expected failures name by key, and the public page written from it (internal module `deviations`).
- The provider's words for those rows, and what a refusal a run saw says of them (internal module `words`).
- A module's review: the pages its REVIEW stands on, kept, and the harness's verdict of each, never the suite's (internal module `review`).
- A run's results: each module's run judged against its entry, the keys observed and computed, the run passed or why not (internal module `results`, for tests).
- A run's report: its results as tables in the ledger's keys and words, what the run cannot show, and the harness's own tests beside (internal module `report`, for tests).
- A run's expected results, module by module, in the ledger's keys, and the package's file of run A's (`expected/a.json`, internal module `expected`).
- The provider as the run meets it (internal module `scene`, for tests): the generated `nextgen-core` and `nextgen-front` run as operators run them behind an https front at the issuer's origin.
- The harness's relying party (internal module `rp`, for tests): a conforming client of nextgen, its JARs, PAR, assertions and DPoP proofs.
- The login screen as the suite's browser meets it (internal module `screen`, for tests): the real SDK with a software authenticator, server-side, behind its own https front.
- The resource the run calls with its access tokens (internal module `resource`, for tests): the harness's, checking the provider's DPoP-bound token and its proof, as nextgen offers no resource server.
- The OpenID Foundation's conformance suite at a pinned version, started and stopped on this machine: `suite` starts and stops it, `api` reaches its API trusting its certificate alone, `compose` composes its containers, `orphans` takes down a suite a killed run left, `commands` holds each program other than docker to its time, `lifecycle` holds what every plan run has (its directories, its stops).

## Not here
- A certification: L1 takes none on a weakened configuration.
- The provider's modules and their own tests.
- Running docker: `docker-client`.

## Offers
- `pnpm --filter @mod/interop-oidf run deviations`: writes `docs/compliance/deviations.md` from `docs/compliance/deviations.json`.
- `suite-pin.json`: the suite's release tag, the commit the tag must name, and the Python packages its scripts run on, each at one version.
- `src/suite/test/suite.integration.test.ts`, run by hand from this package's directory (`npx vitest run <file>`: the workspace's configuration leaves integration tests out): the suite at the pin, up and answering with the harness's certificate alone, and nothing left once stopped (Docker, `git`, `openssl` and Python 3 on the path, and the network).

## Invariants
- No package depends on this one: it is verification, unpublished.
- The suite's tag must name the pinned commit. Everything a start makes is stopped and its directories removed, however it ends, but what stops a suite whose stop failed.
- The suite takes fixed ports, so one runs at a time: its containers carry the process that owns them, and a suite whose owner is gone is taken down at the next start.

## Depends on
- `docker-client` (every docker command). Its tests: `conformance-front`, `create-app` (`./testing`), and the modules the scene and the relying party compose, each by its configuration builder (`client-assertion`, `client-allowance` and `redirect-uris` by `./testing`, `sdk-core-wire`'s `typs`).
