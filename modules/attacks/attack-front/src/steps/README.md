# steps

Internal module of `attack-front`: the compromised Front's steps, F-1 to F-21 of the design note's table, each its own test.

## Responsibilities
- Holds each step: what the Front does (one rewrite or frame of its own, within what crossed it), and where it must be refused, by the Core, the SDK or the relying party's own checks, pinned to its word and cause, with a control where a refusal could have another.
- Holds their world: one default-pattern Core per file, the relying parties and signed clients it registers, a Front per source, people signed up through an honest Front.

## Not here
- The dishonest Front: the package's internal module `front`. The roles (screen, browser, relying party, machine client) and the default pattern's seed: the package's tests.

## Offers
- Nothing to import: its tests are the steps.

## Invariants
- Each step is independent: its own person, session and source; a step that needs a key the Front lacks reuses only what the RP or client sent through it.

## Depends on
- The package's `front`, its tests' roles and pattern.
