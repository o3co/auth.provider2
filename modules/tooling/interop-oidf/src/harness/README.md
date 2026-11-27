# harness

Internal module of `interop-oidf`: a recorded run, the suite against the scene, judged and reported.

## Responsibilities
- Gives the suite what a run needs: its two clients, registered in the scene's signed registry, and the plan's configuration (the server by its discovery, both clients, the resource, the browser and its overrides).
- Records run A: Redis, the scene on it, the user's sign-up, the resource and the suite, every module of the plan in turn; judges it by the expected results and writes its report.

## Not here
- The provider as run: `scene`. The screen and its pages: `screen`. The relying party: `rp`. The resource: `resource`. The suite: `suite`. Judging: `results`; the report: `report`.

## Offers
- `planA`, `variantA`: run A's plan and the variant its expected results name.
- `clientOf` (an id, the plan's alias) → `SuiteClient`: its private key set for the suite and its record for the registry; `callbacksOf` (the alias) → the suite's two callbacks.
- `planConfig` (where the run is reached, the two clients) → the plan's configuration; `browserOf` (the screen, approve or deny) → the browser's tasks; `denied`, the modules the browser denies.
- `startRedis` (a `Docker`, the owner's pid) → `RunningRedis`: its URL and its stop; `serverArgs`, `redisImage`.
- `runModules` (the suite's calls, the plan, a `Timing`, where each module's info and log go, a signal) → each `ModuleRun`; `timingA`.
- `runA` (where its record goes, under `a/`, a signal) → `Ran`: whether it passed, and its report's file; `runAms`, its deadline; `parJarMaxLifetimeA`, PAR's lifetime in it; `outProblem`, why a directory may not hold a record.
- `stoppedWhenEnded` (a signal, a body holding each part by its stop, `Held`) → how the run ended, what the body answered or failed of its own after the signal, each failure to stop; `bodyEndsWithinMs`.

## Invariants
- Each client signs by one ES256 key of its own (a `kid`), at the suite's callback and its twin with the suite's query, bound to DPoP, and asks `openid email`: more than one scope, as the suite asks (#8), each allowed.
- The browser approves on the screen's authorization page, denies for a module in `denied` (#3), and fills a review's placeholder with the screen's page of a refusal it was sent on to (#38): both tasks in the one entry the suite opens, on `/authorize*`, as it runs only that entry's. Each task is optional, each command too, and a module with no placeholder skips the fill.
- Redis 7 runs on loopback under a password of the run's own, `appendonly yes`, `appendfsync always`, `no-appendfsync-on-rewrite no` and `noeviction`, named before it runs and with `orphans`' owner label: a start whose answer was lost is removed by name, and a killed run's is the next suite's start's to take down. One gone already is stopped.
- A module runs to its end or for 8 minutes, then is stopped (`DELETE api/runner/<id>`), its stop awaited, and kept timed out, failing it; one not started is kept so. A failed ask is asked again in its time; a signal ended mid-module ends its wait at once and keeps it aborted, for the suite's stop to take down. Each is judged under the plan's variant, never its info's (the suite adds its defaulted parameters there).
- The expected results are read before anything starts; no module starts past the run's deadline, `runAms`, which the test's time is longer than. The signal ends the run's wait whatever it still waits on: every part held is stopped then, one the body starts after is stopped and the body ended there, and the body is awaited (within `bodyEndsWithinMs`) before the work directory is judged: kept only where a stop failed (its own `SuiteStopFailed` too), its other failures told beside the run's.
- Every part started is stopped however the run ends, each app's output written once stopped, and the work directory (the TLS keys) removed where everything stopped (`lifecycle`'s `cleared`), else named. Once judged, the report is written first and each other record tried after it.
- The record holds the run's client keys (the suite's info and log carry its configuration), so a directory in a git work tree (links followed), or one holding a record already, is refused; the endpoints are read from the discovery document, and a kept page is found by its whole entry.
- Its files are tests': a client's sections are their modules' `./testing`, and the run reads `results`' and `report`'s.

## Depends on
- `scene`, `screen`, `rp`, `resource`, `suite`, `lifecycle`, `orphans`, `review`, `expected`, `results`, `report`, `deviations`; `docker-client`, `conformance-front`; `client-allowance`, `client-assertion`, `redirect-uris`, `sender-binding` (their `./testing`); the login screen's SDK (`Jwk`).
