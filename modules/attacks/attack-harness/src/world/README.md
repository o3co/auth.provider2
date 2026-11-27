# world

Internal module of `attack-harness`: the world a step acts in, on a Core started, for its tests alone.

## Responsibilities
- Makes the relying parties a Core is started with, and the records an operator registers them by.
- On a Core started: its Fronts, each on its own connection and declaring a source of its own, made by the function a harness gives; the screen as the page pins the Core; people signed up (F1) through an honest Front of its own; an authorization started through a Front; a first-key mail's token, the first to an address but those already had.

## Not here
- Starting a Core, and what only a Core of one start has (its process's log, its published keys): their starts', the package's internal module `pattern` and the in-process start. The wire's certificates: `pattern`'s hold.
- The Fronts themselves: `relay`'s honest one, `front`'s dishonest one, a step's own.

## Offers
- `relyingParties` (client ids, a clock) → the relying parties and their records; `world` (`CoreAt`, the relying parties, a Front's maker) → the world, its Fronts of the maker's type; `origin`, `screenOrigin`, `provider`; `Person`, `World`.

## Invariants
- A world never starts a Core and never hands its Core back: what it is given is a Core's wire, its pins, its mail and its stop.
- Each Front and each person of a world has a source no other of it declares.

## Depends on
- The package's `relay`, `roles` and `pattern` (a relying party's record); core-wire's `./testing` (`wireClient`).
