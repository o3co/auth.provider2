# app-output

## Responsibilities
- Writes a generated app around its entries: its manifest, its configuration from the reached packages' fragments, the environment's and the local layer's examples, its network declaration and its guide.
- Maps each fragment's keys to the environment and the local layer: the boundary that keeps module words out of the environment's.

## Not here
- Which modules an app composes, what it reaches, its companions, the promises it requires and its guide's own text: the caller's (`create-app`'s patterns).
- Where the packages come from and what the app depends on them as: the caller's, through `known` and `dependency`.
- What each section means, its fragment (`config.example`) and what it asks (`asks`): each package's own.
- The app's entries and how they boot: `app-entries`. What each network word lets through: `guard`.

## Offers
- `writeApp(target, app)` and `appFiles(app)` (`App`: the modules composed, the packages reached, the companions, the promises required, `known`, `dependency`, the guide's title, use and card): the files, then written.
  - `package.json`: `start`, each entry's script and each companion's bin as a script; the kernel, `config-files`, every module and companion as dependencies.
  - The app's entry and each entry's file (`app-entries`); `config/application.conf`, `config/local.conf.example`, `.env.example`; `network.json`; `.gitignore`; `README.md`.
- `Known`, a package as the caller read it; `Ask` and `Asked`, what a package declares for the guide; `Process` and `Word`, `network.json`'s entries; `fragmentsIn`, `fragmentFile` and `settingsOf` (`Fragment`, `Tree`, `Setting`).

## Invariants
- A target that holds anything, or is no directory, is refused, never overwritten; an empty name is refused, never read as the current directory. Every file is made before any is written: a refusal writes nothing.
- Fragments, `asks` and network words are read over the packages reached, in their order, a package with no module (`kernel`) among them.
- A fragment holds exactly one section, read as data: no substitution, no include, no backtick or control character, within 64 KiB of text and 32 KiB of keys and values. A second fragment of a section is refused.
- The configuration file reads each scalar key from its variable (the key path joined by `_`, upper-cased, `-` as `_`) and holds no value, but `promises.required`, written only where the app requires a promise, and refused at generation where `promises` is not reached. Two keys reading one variable are refused.
- Lists and values of several lines go to the local layer's example; neither example holds a live line.
- An `asks` line is a value, a decision (`decides`), an acceptance, or a step the operator runs, named by its entry; a line marked `unadapted` is left out where an adapter of its package is reached, and `{adapters}` is the reached adapters' `registersAs`. The lines come in the packages' order; the order of the steps is the pattern's card's.
- A companion is kind `companion` with exactly one `bin`, run as `node node_modules/<name>/<bin>`. A script two would take, a companion's among them, is refused, as is a path the entries and app-output would both write.
- `network.json` is `{ processes }`, one entry per process: the app (`start`, its entries, which assemble the same composition and never start, accepting nothing) and each companion. Each holds `{ word, from }` as the manifests state them, nothing derived: the app's over the reached packages, a companion's over it and the workspace packages it depends on. It is the input to enforcement, not enforcement.
- Git leaves out every env file but `.env.example`, the local layer, `*.pem`, `*.key` and `*.jwk`.

## Data
- Writes the target only; reads its template and the fragment files of the packages given.

## Depends on
- `app-entries` (the entries, `kernel` and `configFiles`); the HOCON library.

## Vocabulary
- fragment: a package's example of its section, placeholders only; a secret's is `REPLACE-…` text its section refuses.
- local layer: the operator's configuration file layered first, for lists and values the environment does not carry.
- companion: a program of its own, outside the provider's process, the app runs beside it.
