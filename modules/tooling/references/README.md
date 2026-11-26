# references

## Responsibilities
- Writes each module's section's defaults as `reference.conf` beside its package's manifest, from the section's schema: each key described, with its default or what it needs, a nested object's own description before its keys, a key held only once an optional object is set or in some variants as a comment saying when.
- Checks that every `reference.conf` is the one it writes, and that none lies where no section is.

## Not here
- What a section holds, its defaults and descriptions: each module's schema. Loading configuration: the kernel; `reference.conf` is for reading, the module applies its defaults itself.

## Offers
- `sectionsIn` (packages → each module's section, by its `./module` export's `section`, and the kernel's, by its contract's `kernelSection`): name, owner, directory, rows (`rowsOf`) and described objects (`describedOf`).
- `referenceConfOf` (a section → its `reference.conf` text) and `referenceConfFile` (a package's directory → its path).
- `pnpm --filter @mod/references run configuration`: writes every section's file.

## Invariants
- A file is read only from the schema: a key, its JSON Schema type and default, its description, and whether it is required, within an optional object or under a variant of a union told apart by one key.
- The test of this package fails where a file differs from what it writes, or a package without a section holds one: the files never drift from their schemas.

## Depends on
- `guard-imports` (`readWorkspace`, `Pkg`); each module's `./module` and the kernel's contract, read at run time.
