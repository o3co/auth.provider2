# axes

Internal module of `combinations`: each axis's adapters and its default, as the workspace and the packages beside it declare them.

## Responsibilities
- Reads which owner each adapter serves, and which of an axis's adapters is its default.

## Not here
- Where an axis's default comes, and what a selection names for it: the package's composing.

## Offers
- `axisOf` (a package): the owner it replaces or adapts. `axesIn` (the declarations): each owner's adapters, `defaultOf` (owner) and `replacingOf` (owner), the default declared to replace it.

## Invariants
- An axis is its owner's: an adapter `replaces` the owner (composed instead of its module) or `adapts` it (beside it). Its default is the one adapter declaring `default`, or its only one.
- An adapter declaring `neverDefault` is never the default, even the only one: it comes only where a selection names it for its axis.
- An axis's only adapter in the workspace stays its default beside an adapter declared outside; an outside adapter declares no default of an axis the workspace owns.

## Depends on
- The package's `declared` (the packages' declarations).
