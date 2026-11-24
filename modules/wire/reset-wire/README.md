# reset-wire

## Responsibilities
- Holds the words of a reset (V22): the instruction an embedder's recovery service signs to send a subject back to the first key's path, the window it is taken in, the faults a reset is found with, and the answers of a reset not placed, from one place for the embedder, the monitor's rule and the Core.

## Not here
- The log's words for a reset: the `typ`s (`reset-instruction+jwt`, `reset-boundary+jwt`), the boundary record's kind and body, the op id `reset:` and the signer set's count: `transparency-wire`.
- Signing and verifying an instruction, and the rule that finds a reset's fault: the embedder, and `authority-rules`.
- The answer of a placed reset (an append's) and the union of the two: the log's, and the Core's `transparency`.

## Offers
- `resetInstruction`: the instruction's payload schema (`ResetInstruction`): `v`, `installation`, `subject`, `action` (`reset`), `kg`, `id`, `iat`, `exp`.
- `instructionLimit` (8192): the longest a signed instruction is, its compact JWS in bytes.
- `resetLifetime` (600) and `instructionSkew` (60): the longest an instruction lives and how far an embedder's clock may stray, in seconds.
- `resetFaults` (`ResetFault`): `shape`, `set`, `signature`, `installation`, `subject`, `op`, `generation`, `time`, in the order the rule checks them.
- `resetRefusal` (`ResetRefusal`): `schema` reads a reset not placed, `invalid` (fault) and `conflict` () make one.

## Invariants
- A protocol (G33): types, frozen constants, fixed schemas and the functions that build by them; no I/O, clock, randomness or state. It depends on no package of the workspace, the log's contract among them (G2, G6).
- An instruction refuses a field it does not know and a `v` other than 1; its `installation` and `subject` are 1 to 255 UTF-8 bytes, so a compact one signed by any key the protocol takes stays well under `instructionLimit`. One longer, however padded, is refused as `shape` by its placer, as the CLI reads no longer line; its `id` is 22 to 43 base64url characters (128 bits or more, a nonce too), and it is issued before it expires, living `resetLifetime` at most.
- A reset is taken from `iat` less `instructionSkew` to `exp` plus it, read in milliseconds against the log's acceptance time.
- The first six faults are forged; `generation` and `time` befall an honest monitor too: the reset is verified but does not take, so a placed reset is not one that took.
- A reader tells a reset's answer by `result`: `invalid` or `conflict` is this wire's, any other an append's.

## Depends on
- Nothing in the workspace; `zod` (a peer).

## Vocabulary
- reset (回復): sending a subject back to the first key's path, its key generation one on. instruction (reset の指示): the embedder's signed request for one. key generation (鍵の世代): the count of resets and erasures that took.
