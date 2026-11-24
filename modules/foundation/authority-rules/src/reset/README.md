# reset

Internal module of `authority-rules`: a reset boundary's rule (kernel-spec §6.1's J0r and §6.2, V22).

## Responsibilities
- Finds a reset boundary's verdict and outcome, and the fault that stops it, from its body, its flow's state before it, the caller's verification, the installation and the reset instruction's signer sets.

## Not here
- Verifying a signature, and reading the publisher's flow for the sets of each version: the caller's (`Checks`, `ResetContext`). Placing a reset (the monitor's) and its answer: `transparency-local`, `transparency`. The instruction's and the faults' words: `reset-wire`; the boundary's body and op id: `transparency-wire`.

## Offers
- `resetFinding` (body, state, checks, context, acceptance time) → `ResetFinding` (verdict, outcome, fault); `ResetContext` (installation, `sets` by version: keys, `absent`, or none where unread).

## Invariants
- The faults in `resetFaults`' order, the first that holds named. `shape` (past `instructionLimit`, or the body or payload not reading as the log reads JSON), `set` (the publisher's flow holds no set of the version), `signature` (no key of that set verifies it as `reset-instruction+jwt`), `installation`, `subject` (another than the flow's, or a flow not a subject's), `op` (not `reset:` and the instruction's id): forged, not taking.
- `generation` (its `kg` is not the key generation before it) and `time` (accepted outside `iat` less `instructionSkew` to `exp` plus it, in ms): verified, not taking, so a placed reset is not one that took.
- A set version not yet read, or no reset context given, holds it, uncounted: a configuration that places resets always gives the context, or every reset placed stays held and its instruction's id spent.
- `judge` holds a reset boundary's body, where it reads, to its envelope's flow, op and previous position, as `signedRecord` holds every other's; one that does not is a TypeError, the caller's to drop. The op derived from the instruction is this rule's `op`.
- A reset that took moves the key generation on in the fold, as an erasure boundary does; any other moves nothing.

## Depends on
- `reset-wire` (the instruction, the window, the faults), `transparency-wire` (the boundary's body, the typ, the op id, the one JSON reading), the package's `evidence` (`Checks`, `Context`) and `fold` (`FlowState`).
