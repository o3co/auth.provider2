# dependencies

Internal module of `guard-imports`: G2, G10, G14, G16 and G36, what a package may depend on, by its kind and its manifest's.

## Responsibilities
- Holds each package's workspace dependencies, as its manifest names them, to its kind's place in the kinds' order and to its manifest's declarations:
  - G2: the bottom level of the kinds' order (common, protocol) depends on nothing in the workspace (its `G1, G2` line on the package's card).
  - G10: kind direction: a lower kind never depends on a higher one, by each manifest's kind; a test dependency may point up to the wiring kind only. No kind, or one `kinds` does not know, is refused.
  - G14: a verification base depends on no product module.
  - G36: a package of another kind than verification names no verification package in its run-time dependencies (`dependencies`, `peerDependencies`); its `devDependencies` may, so its tests use fakes and harnesses.
  - G16: a feature depends on no capability, nor on a package declaring `forWiring` (a feature's storage is its wiring's to build on it); its tests may use their `./testing` stand-in. `forWiring` is `true` only.

## Not here
- The kinds' order and roles: given by the caller (`Rules`). G1 (no cycles) and the imports' own rules: the package's `rules`.

## Offers
- `dependencyRules` (a scope, a package): each rule above, reported through the scope.

## Invariants
- A package depends on what its manifest names in `dependencies` and `peerDependencies`, and in `devDependencies` where a rule counts tests (G2, G10, G14, G16 do; G36 does not).

## Depends on
- The package's `scope` (the scope and its rules), `rules` (`packagesUsed`, a file's edges to packages) and `workspace` (`Pkg`).
