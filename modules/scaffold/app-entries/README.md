# app-entries

## Responsibilities
- Writes a generated app's entries, its start and the scripts its composed modules call for, and holds how each boots, refuses, checks 0.17's variables, writes and stops.

## Not here
- The project's files around them, its manifest, configuration, image and guide (`app-output`); what each module's script runs (that module, through its contract).

## Offers
- `mainSource` (the composed modules, what each is imported as, where the operator writes each key the configuration reads) → the app's entry, which `start` runs.
- `entriesOf` (the composed modules, what each is imported as, the command that runs a file, where keys are written, what the composed packages declare in `appEntries`) → each entry's script and file.
- `KeysWritten`: where the operator writes the keys the configuration reads: each one's variable, those of several lines, and the local layer.
- `startSource` and `permissionLinesSource` (internal module `launcher`): the app's start, which `start` runs, and what it loads ahead of the entry where it holds it.
- `kernel`, `configFiles` and `appPermissions`, the packages every app depends on (its entry reads its configuration files through `config-files`; its start makes Node's flags through `app-permissions`).

## Invariants
- The app reads the configuration files `APP_CONFIG` lists, comma-separated, layered in order; the generated configuration file when unset.
- The app exits 78 on a refused boot, told by the kernel's mark (`BootRefused.is`), writing each refusal on standard error, every line handed on before it exits.
- A refusal of a key the configuration reads from the environment says, after its reason, where to write it: its variable in `.env`, or the key in the local layer (the local layer alone for a value of several lines); a refusal of anything else is written as it is. The hint comes from a table written when the app was generated, from what writes `application.conf`: an app whose configuration files changed since may be told of a variable they no longer read.
- The app's entry checks, as it boots, the variables 0.17 read that the environment sets and no configuration file reads, by `config-files`' `legacyVariablesCheck` alone: its warning goes once to standard error as `warn config-files:` and boot goes on; its refusal refuses boot. `APP_LEGACY_VARIABLES` (`warn`, `refuse`, `ignore`) chooses, read there.
- The app's start holds the entry under Node's permission model, as `APP_PERMISSION` says, and runs it in its own process (internal module `launcher`).
- SIGTERM or SIGINT stops the app, draining; one that comes while it starts stops it once started, and a second one waits for the first stop instead of stopping again.
- Each entry a composed package declares in its manifest's `appEntries` is written by its shape, and boots, reads, writes and exits as internal module `entries` says.

## Data
- Reads its templates; writes nothing, handing each file's text to its caller.

## Depends on
- Nothing in the workspace.
