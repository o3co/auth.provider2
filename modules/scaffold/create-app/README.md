# create-app

## Responsibilities
- Generates an app from one of three patterns: `nextgen-front`, `nextgen-core` and `nextgen-dev`, each naming every axis it composes, the promises it requires and the companions it runs.
- Tells, as it generates, each composed adapter that declares itself never a default, in that adapter's own words.

## Not here
- What a selection composes and reaches: `combinations`. The files of the app: `app-output`. Its entries: `app-entries`.
- What each module asks of the operator and its sample section: each module's `asks` and fragment.

## Offers
- `create-app <target> --pattern <name> [--add <name>]... [--axis <owner>=<adapter>]...`; `create-app --list`; `--help`. A name without a scope is `@mod/`'s. Exit 0 once written, 64 for a usage error, 1 for an app it cannot make (a target holding anything, a composition refused), told on standard error.
- `run` (the arguments, `Io`), `generate` (a target, `Plan`: a pattern, what is added and chosen) → the notices told.
- `patterns`, `patternNamed`, `patternOf`, `Pattern` (name, use, features, axes, add, required, companions, card); `selectionOf` (a pattern, what a plan adds and chooses) → its `combinations` selection, for a test composing a pattern as an app does; `noticesOf` (a selection) → its notices.
- `./testing`, for a test running a generated app as an operator runs it; its configuration is the test's, from each module's `./testing`:
  - `generated` (a `Plan`) → the app in a temporary directory, each dependency linked to the workspace, its manifest (a companion's entry in its `scripts`), its notices, and its removal.
  - `running` (its directory, a file, a configuration, an environment, arguments) → `Running` (its output, its exit, its stop: SIGTERM, SIGKILL past 10 seconds): the configuration in its local layer first (`APP_CONFIG`), one configuration in a directory at a time. `listening`, `freePort`.
  - `asOperator`: a configuration split into the environment `.env.example` names and the local layer.

## Invariants
- The patterns, each axis named:
  - `nextgen-front`: `http-ops`, `front-relay` for http (added: no feature reaches it), `metrics-prometheus`. No key, log, store or authentication.
  - `nextgen-core`: the Core's features; `core-wire`, `metrics-log`, `keys-kms`, `transparency-local`, `redis`, `mail-smtp`, `users-local`, `audit-http`, `clients-registry`. It requires `front-compromise-new-authorization` and `front-compromise-client-token`.
  - `nextgen-dev`: the same features; `in-process`, `metrics-prometheus`, `keys-local`, `transparency-local`, the memory `store`, `mail-smtp`, `users-local`, `audit-stdout`, `clients-registry`; companions `publish-serve` and `registry-sign`. It requires nothing.
- The Core's features leave `client-credentials`, `sign-up`, `userinfo` and introspection to `--add` (V21, V27). Requiring `no-client-subject-token` is the operator's, recommended only where no machine client is registered.
- `promises.required` is the one value a pattern writes; every other value is the operator's, from the modules' fragments.
- A notice is each `asks` line of a composed adapter declaring `neverDefault`, however it came (an axis or `--add`), written as `notice: <adapter>: <line>`.
- Departures recorded: `keys-kms` stays the keys axis's default (G25 asks one), where P3 asked none; making keys at each start of a development app is `trial`'s, a later group; the network declaration's extension (purpose, destination kind, caller) comes after `network.json`, before any renderer, where arch-review S3 had it first.
- It generates into the workspace it lies in, every dependency a `link:` to a workspace package: nothing is published here.
- A process `./testing` runs takes an environment built whole: of the run's variables, `PATH` alone reaches it, with what the caller gives; `APP_CONFIG` is always its own. Files of the account (an SDK's lookup in the home directory, such as `~/.aws`) are the caller's to shut out, by the variables that name them.

## Depends on
- `combinations` (`composed`, `reached`), `app-output`, `workspace-packages`.
