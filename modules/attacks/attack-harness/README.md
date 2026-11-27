# attack-harness

## Responsibilities
- The attack harness of a compromised Front (claims 1, 1b and 2): the dishonest Front a step relays through, over the wire alone (internal module `front`), and the steps themselves (`front-steps`).
- The attack harness of a compromised Core, at L0 up to the monitor's judgment (claim 3 is not held at L0, as its start is judged): a Core in the test's process (`in-process`) whose bad writer places records its evidence does not hold, the steps themselves (`core-steps`), each judged forged by the rule it names, the Core then taking none in.
- What its harnesses share, each an internal module for its tests: relaying as an honest Front does (`relay`); the harness's Core (`nextgen-core`, as create-app composes it) and its start in a process of its own (`pattern`); the roles a step plays (`roles`); the world a step acts in on a Core started (`world`).

## Not here
- The Core's modules and their own tests; the receivers' checks (R16 to R18), a log and a monitor apart from the Core, and a Store written outside the judgment: at L1.
- The patterns and an app generated from one: `create-app`, whose `nextgen-core` selection `pattern` takes.
- Anything a product reads: it is verification, unpublished.

## Offers
- `badFront` (the wire, the source it declares) and `honestRelay` (the same), with the Front's contract (`Front`, `Sent`, `Answered`, `Wire`), for the harness's own tests.

## Invariants
- The Front holds no screen's or relying party's key: it reads only the wire's words.
- The tests reading the SDK are typed by the root's `tsconfig.sdk-tests.json` (the DOM's types), apart from the root's.
- No verification package depends on this one, in its devDependencies either: guard's G14 would then hold it to no product module, and its tests read the whole Core. So the harnesses that share its Core, roles and world are its internal modules.
- Its internal modules read one another one way, as its own test of directions holds them, every edge counted; none of them reads the package's entry. That test stands until guard holds a package's internal modules to a direction.

## Depends on
- `front-core-codec`, `front-core-wire` (an operation as HTTP and as a frame).
