# Contributing

This guide covers how the repository is laid out, what a change must pass, and how commits and pull requests are shaped.

## Before you start

- **Node 24 or later** (`.nvmrc` names 24), and **pnpm** at the version `packageManager` in `package.json` names; `corepack enable` gives you that one.
- `pnpm install`, then `pnpm check` should pass on a clean checkout.
- **English only**, in code, comments, documents and commit messages; the Japanese README is the one exception (see Commits).
- **A vulnerability** is reported privately, as the [security policy](SECURITY.md) says, never in an issue or a pull request.

## Where a change goes

- **Modules.** Each concern is one module under `modules/<group>/<name>`, a package of its own. Its README, the module's card, is its contract: responsibilities, what is not its own, what it offers, its invariants, its data, what it depends on and its vocabulary.
- **One word, one meaning.** A word keeps one meaning inside its module. Where a module meets another's words, it maps them at its boundary rather than taking them in.
- **Cards hold the current contract only.** Plans, moves in progress and removals to come are not written in a card.
- **Receivers' packages** live under `sdk/`, a workspace of their own. They depend only on the protocol packages.

## Checks

| Command | What it runs | Where CI runs it |
|---|---|---|
| `pnpm check` | type check, lint (Biome), unit tests (Vitest) | every pull request, on Node 24 and 26 |

The required check is `build-and-test`. More checks join as the modules that run them arrive.

## Tests

- **Write the test first**, and see it fail for the reason you expect.
- **Contract tests.** A module publishes the tests of its contract at `./testing`; an implementation runs them against itself.
- **Integration tests** end in `.integration.test.ts`, and fail rather than skip when the outside system is missing.

## Commits

- **The README in two languages.** `README.ja.md` is a full translation of `README.md`; a commit that changes one changes the other.
- A commit says why, not only what; the diff shows what.
- **Conventional Commits**: `feat(<module>): …`, `fix(<module>): …`, `docs: …`, with `!` after the type for a breaking change.
- **One module per commit.** The card changes in the same commit as the code it describes. A module taken from auth.provider arrives in its new form in one commit: moving it and reshaping it are not split.

## Pull requests

- Open pull requests against `develop`. `main` takes releases.
- Describe the change, how you tested it, and any setting, route or behavior an operator would notice.
