# guard (sdk)

## Responsibilities
- Checks that the receivers' parts depend on the provider's protocol packages alone, each finding reported by its id, place and what went over:
  - S1: each dependency, in every dependency field apart, is a package of the provider's workspace whose kind is `protocol`, by a `link:` to its directory, whose manifest names that dependency; any other, a third party's or another sdk package's too, is refused.
  - S2: a source names its own package's files (by their real paths) and its dependencies alone, no subpath of one, and in shipped code no triple-slash type or lib reference; a test names `vitest`, Node's builtins and Node's types besides. A package holds no symlink.
  - S3: the sdk's pnpm pin and supply settings are the provider's: every top-level setting of the provider's `pnpm-workspace.yaml` but its packages is the same here, a block of entries (such as `overrides`) holding a subset.

## Not here
- The provider's workspace rules (kinds, budgets): the provider's own guard. The cards of the packages here are measured by it too, by its card rules alone (G7).
- A specifier named at run time (a template, a variable): not read; review's.

## Offers
- `sdkViolations` (the sdk's root → the findings), and the check command (`pnpm guard` at the sdk's root).

## Invariants
- A package's files are all but its `node_modules`, dot-named ones too.
- The packages are the directories under `packages`; the provider's workspace is the repository root beside the sdk, its packages as its `pnpm-workspace.yaml`'s globs name them. Nothing is enumerated.
- A file's references are its imports, re-exports, import types, dynamic imports, requires and triple-slash references, as TypeScript's pre-processing reads them, in every script extension.
- A test is a file under the package's own `test` directory, or one named `*.test.*`.

## Depends on
- `typescript`.
