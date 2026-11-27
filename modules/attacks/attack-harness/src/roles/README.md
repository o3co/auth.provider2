# roles

Internal module of `attack-harness`: the parties a step plays beside the Front, for its tests alone.

## Responsibilities
- The login screen as a page runs it on the real SDK (a login, by value or under PAR by the client and `request_uri` alone, holding no JAR, approved or denied by the person, the denial sent to the RP alone; a sign-up, a first key, a key added, deleted or renamed), its requests sent through the Front given.
- The browser holding its passkeys; a relying party making its JARs, DPoP proofs and token requests and checking what it is given (a callback, a code's or a denial's, at R3 and R4); a machine client of a signed registry asking its own token.

## Not here
- The Front a role sends through: any `Front` of the package's internal module `relay`, the honest one or another.
- The Core, its pattern and its start; what a step expects.

## Offers
- `loginScreen` (pins, a browser) and `stopped`; `browser` (the screen's origin) and `attestedKey`; `relyingParty` (the provider, a client id, a redirect URI, a clock), `dpopKey` (a clock), `claimsOf`, `es256`, `p256`, `thumbprint`; `machineClient` (an id, the provider, a key, a clock); `Clock`, `realTime`. Each in its own test file, imported by its path.

## Invariants
- A role holds its own keys alone, and reads a Front only through `post`: it tells the Core's refusal from the Front's by the wire's reply the answer carries.
- A relying party and a machine client date what they sign (a JAR, a client assertion, a DPoP proof) and read an ID token's `exp` by the clock given, the real time unless given, so they reach a Core on a test clock.
- Its files are tests' (`test/`): they read the SDK, typed by the root's `tsconfig.attacks.json`.

## Depends on
- The package's `relay`; the login screen's SDK, `sdk-core-wire`, `webauthn`'s software authenticator.
