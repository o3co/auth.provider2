# interop-oidf

## Responsibilities
- The ledger of the provider's intended deviations and strict choices (L1), `docs/compliance/deviations.json`, which a conformance run's expected failures name by key, and the public page written from it (internal module `deviations`).
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
- `docker-client` (every docker command). Its tests: `conformance-front` (`selfSigned`).
