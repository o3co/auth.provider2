# files

Internal module of `guard`: G35, that product code touching files declares what it reads and writes.

## Responsibilities
- Finds a product package's or a companion's shipped code that loads Node's file system, and holds the package to a `permissions` declaration in its manifest, one `app-permissions` takes.

## Not here
- What `permissions` may say, and what the launcher grants from it: `app-permissions`. Whether a declaration says all that the code reads: the permission model's audit, at run time.
- A library reading files for a package (`prom-client`, the AWS SDK): outside this rule; the audit alone holds it.

## Offers
- `filesRules` (G35), `touchesFiles` (a file's facts → whether it loads the file system).

## Invariants
- A file loads the file system where shipped code imports or re-exports a value of `fs`, `node:fs`, `fs/promises` or `node:fs/promises` (a type alone is none; an import for its effect is one), or loads one by `import()`, `require` or `import = require`, read from `guard-imports`' facts as G26 reads them.
- A product package or companion with such a file declares `permissions` (an empty one is a declaration: its code alone), and its declaration has no problem `permissionsProblems` names; each problem is reported at the package. Without one, each such file is reported. No package is excepted by name.

## Depends on
- `guard-imports` (each file's facts), `app-permissions` (`permissionsProblems`); the package's `kinds` (the kinds read) and `units` (what counts as a test).
