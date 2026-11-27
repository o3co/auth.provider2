# in-process

Internal module of `attack-harness`: a Core of the default pattern in the test's own process, for a harness playing a compromised Core; for its tests alone.

## Responsibilities
- Starts the default pattern here on a test's clock, with the relying parties given dated by the same clock, and builds the world on it, its Fronts made as given.
- Hands a harness the compromised Core's powers as ports, in its own words: writing on its log (a record placed after its flow's head, the flow's head, a record, when it was taken, and its judgment at a position, a reset instruction placed), and opening a continuation sealed to it (its body's text and signature).
- Reads what the keys' owner holds, writing nothing: a live key's subject and registration, a subject's credentials and its reservation waiting (the key reserved, as attested).
- Places an honest operator's reset through passkey-reset, where the spec composes it.

## Not here
- The Core assembled, its stores, its keys or any contract beyond these ports: none is handed out.
- The seed and its start in this process: the package's internal module `pattern`. The world: `world`. What a record holds: the caller's (authority-rules' `./testing`).

## Offers
- `inProcess` (an `InProcessSpec`, a Front's maker, a `TestClock`) → the world, `judged` (each promise its composition stands on and whether it holds, as judged at its start), `writer` (`Writer`), `opener` (`Opener`), `keysRead` (`KeysRead`), `setup` (`Setup`, where composed), the clock and `stop`; `testClock` → `TestClock`; `Flow`, `Placing`, `AtPosition`, `SealedSent`, `InProcess`.

## Invariants
- A port's answer is in its words: a record placed or the log's refusal by its word; a reset placed or refused; a continuation opened or `unopened`.
- The test's clock is the real time moved on by what the test advanced, the Core's and the roles' alike.
- Its files are tests' (`test/`), typed by the root's `tsconfig.attacks.json`.

## Depends on
- The package's `pattern`, `world`, `roles` (a clock's type) and `relay` (a Front's type); `transparency`, `keys`, `passkeys`, `passkey-reset`, `continuation-wire`, `sdk-core-wire`, `promises` (the contracts and words its ports read).
