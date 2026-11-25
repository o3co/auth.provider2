# attack-front

## Responsibilities
- The attack harness of a compromised Front (claims 1, 1b and 2): the dishonest Front a step relays through, over the wire alone; and in its tests, the default pattern's seed (a whole Core composed, the check that it boots, and its start in a process of its own), the roles a step plays (the login screen on the real SDK, its browser, the relying party), and the honest flow they make through the Front.

## Not here
- The Core's modules and their own tests; a compromised Core (claim 3): at L0 the monitor's judgment, in `authority-rules`' and `transparency-local`'s tests; the receivers' checks (R16 to R18), at L1.
- The default pattern's package (M4): its seed is in the tests here.
- Anything a product reads: it is verification, unpublished.

## Offers
- `badFront` (the wire, the source it declares), from its internal module `front`, for the harness's own tests.

## Invariants
- The Front holds no screen's or relying party's key: it reads only the wire's words.
- The tests reading the SDK are typed by the root's `tsconfig.attacks.json` (the DOM's types), apart from the root's.

## Depends on
- `front-core-codec`, `front-core-wire` (an operation as HTTP and as a frame).
