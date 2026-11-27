# app-permissions

## Responsibilities
- Holds the language a package states what it does beyond its code in (its manifest's `permissions`): the files its section's keys name, literal paths, files variables name, the files it writes, and where its `forks` start a process.
- Holds an app's processes' permissions in no runtime's words (`permissions.json`), and makes Node's permission flags from them, the configuration and the environment, for a launcher to start the process with (§8.1).

## Not here
- Which packages a process composes, their sections and fragments, and writing `permissions.json`: `app-output`. Starting the process with the flags: `app-entries`' launcher. What a configuration's load read: `config-files`.
- Whether a package that touches files declares it: `guard`.

## Offers
- `Permissions` (`read`: `keys`, `paths` with `file` or `dir`, `env` with a default and whether its reader expands `~/` in the value (`home`); `write`: `keys`, `beside`; `child`: `when` a key of the section is a value) and `permissionsProblems` (a value → why it is no `Permissions`; an empty one is code alone).
- `ProcessPermissions` (`code` roots, `declared` packages with their section, permissions and whether they fork, `network`), `AppPermissions` (version 1, by each process's script), `appPermissionsOf` (`permissions.json`'s text → the permissions, or each problem).
- `nodeSettings` (a process's permissions, and `NodeInputs`: the mode, the configuration and what its load read, the environment, the home directory, the working directory, the app's own directory, whether this Node takes `--allow-net`) → the flags and the packages a child-process grant is for, or where a value that cannot be granted came from, and why. `Mode` and `modes` (`enforce`, `audit`, `off`), `atKeyPath` and `valuesAt` (what a key path holds), `lookupsAbove`, `ConfigReads`.
- `homeOf` (the environment, the system's home, its separator) → the home directory as the environment's readers take it: `HOME`, `USERPROFILE`, `HOMEDRIVE` and `HOMEPATH`, then the system's.

## Invariants
- A key path is lowercase words joined by `.`, `*` a whole word for each element of a list, never first; a condition's key has no `*`. Literal paths are absolute; a variable's default may begin `~/`, the home directory.
- `enforce` is `--permission`, `audit` `--permission-audit`, each with the same grants; `off` is no flag.
- Read grants: the app's own directory (by its real path where it runs, so a moved app is still its own root) and each code root, and every `node_modules` above each (where a library looks a package up).
- Read grants also: the configuration's reads and the paths it probed, the strings each key path names in the package's section (a relative one against the working directory; any other value names no file), each literal path, and each variable's file, its value read as its reader reads it (`~/` the home directory where `home` says so, else literally; its default where unset or empty, `~/` there the home directory).
- No write is granted: the write forms stay declared for the entries' later step. No worker, addon, WASI or inspector is granted, and the language has no word for them.
- A grant reaches what Node reaches through it: a link inside a granted tree reads its target, and every `node_modules` above a root is read. Keep secrets outside every granted tree and every target its links reach.
- Child processes are granted where a composed package forks: always without a condition, else where its section's key path holds the value; an unset key does not hold.
- The network is granted where a composed package reaches it and this Node takes the flag (Node 24 takes none and holds no network).
- A path holding `*` or `,` refuses, naming where it came from (the section's key, the variable, `APP_CONFIG`), never the path: Node reads them in a grant as its own.

## Left to you
- A declarer of `child.when` tests, in its own package, that the key is a key of its section's schema, the value one of the key's values, and the schema's default not the value, as the launcher reads no schema.
- A declared file key is in the package's fragment (`config.example`), optional ones too: `app-output` refuses a key its fragment lacks.

## Depends on
- node's `path`. No workspace package.
