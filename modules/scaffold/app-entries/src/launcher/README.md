# launcher

Internal module of `app-entries`: the app's start, which holds the app's entry under Node's permission model.

## Responsibilities
- Writes the app's start (`start.ts`), which makes Node's permission flags from `permissions.json` and the configuration and runs the entry in its own process under them, and what the start loads ahead of the entry (`permission-lines.ts`).

## Not here
- The flags themselves, from a process's permissions: `app-permissions`. `permissions.json`, and the `start` script running the start: `app-output`. The entry: the package's `start`.

## Offers
- `startSource` (what each package is imported as, where keys are written) → the start's text; `permissionLinesSource` → the preload's text; `appPermissions`, the package the start imports.

## Invariants
- The start reads `APP_PERMISSION`: `audit` (unset or empty: the default until every path an app runs shows no event under it), `enforce` or `off`; any other refuses with 78, naming the variable, never its value.
- Held (`enforce` or `audit`), it reads `permissions.json`'s `start` and the configuration with what its load read (`loadConfigReading`), makes the flags (`nodeSettings`, the app's own directory, where it runs, its first root; the home directory by `homeOf`), and runs the entry by `execve`: the same pid, the entry's signals and exit code its own, its own flags (`run`'s hardening) and arguments carried on, `permission-lines` loaded first.
- `off` runs the entry so with no flag. `audit` on a Node that takes no `--permission-audit` refuses with 78.
- A configuration the entry would refuse, `permissions.json` missing, malformed or with no `start`, a value that cannot be granted (named by its key or variable, never its path), or an `execve` that fails in any mode, is refused by the start in the entry's words (the same `refused` part) and 78; the entry never starts.
- `permission-lines` writes, under `audit` and `enforce`, a first line naming how the entry is held (`app-permissions.held`, its mode as the runtime holds it: `none` where no permission model is on), then each of the model's events (`app-permissions.event`, its kind and fields) as a JSON line on standard error, so a read refused and taken for "not there" is still told.
- Each line is written whole before the event goes on, waiting while the pipe is full: an exit right after drops none, and a slow reader holds the app, never ends it; one that stops reading stops it, its signal handlers too, until it reads again. A write failing otherwise is let go.
- Where `process.stderr` still holds text, a line starts a line of its own: it may come before that text's rest, never inside a line.
- The start warns of a child-process grant, naming the packages it is for (`warn app-permissions:`). `--print` writes the command for this configuration and mode, `off` too, as JSON, instead of running it: true for that configuration alone.
- On Windows (and `os400`), where no entry starts in place, `off` imports the entry by its URL in the start's process; `audit` and `enforce` refuse, telling to set it to `off`.

## Depends on
- The package's `start` (`filled`, `refusedPart`, the packages every app depends on).
