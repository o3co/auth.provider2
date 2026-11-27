# suite

Internal module of `interop-oidf`: the suite at its pinned version, started and stopped.

## Responsibilities
- Starts the suite at the pin: its source at the pinned tag, a Python of its own for its scripts, its containers under a Compose project of their own in a directory of its own, after any suite whose owner is gone was taken down; and stops it, leaving nothing behind.

## Not here
- What a plan does with the suite: the plan's run.
- The certificate it answers with: the caller's, one naming the suite's host (`conformance-front`'s `selfSigned`, in the tests).

## Offers
- `suitePin` (the package's `suite-pin.json`, or a path) → `SuitePin`: the release tag, the 40-hex commit it names, one or more Python packages each at one version; refused where it is not one.
- `startSuite` → `Suite`: its scripts, its Python, the certificate's file, `api` (a GET taking a 200 alone), `call` (any method the API takes, its status answered as it comes), `stop`. `SuiteStopFailed`: a stop that failed.
- `suiteOrigin`, `https://localhost.emobix.co.uk:8443`. `hostForSuite`: the name the containers reach this machine by (`host.docker.internal`) and the address to listen on; on Linux, the bridge's gateway in IPv4.

## Invariants
- The tag must name the pinned commit, or the start fails before Compose is asked for anything.
- The suite must answer within 360 seconds, as long as its own runner waits; each setup step and each request to its API is held to the plan's deadline besides its own time. Its nginx answers with the caller's certificate, trusted alone by its fingerprint.
- Stopping keeps every container's state and log first, both streams, then takes the containers and their volumes down, past the deadline by budgets of its own, and removes the directory. A failed start stops what it started; one failing before Compose removes what it prepared alone.
- A stop that fails, a failed start's own too, is a `SuiteStopFailed` telling every step that failed; where the containers were not taken down, the directory stays, holding what stops them.

## Depends on
- `api`, `commands`, `compose`, `orphans`; `docker-client`; git, Python 3 and Docker on the path, and the network for the suite's source and images.
