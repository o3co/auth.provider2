# passkey-reset

## Responsibilities
- The reset's path in the Core (V22): hands an embedder's signed reset instruction to the transparency log, and where it was placed, takes the boundary in and settles the subject's passkeys, answering the log's answer; tells a subject's key generation for an instruction on L0's path.
- Declares where the reset's path stands on the promise of a new login.

## Not here
- Whether a subject may be reset, waiting, telling and undoing: the embedder's recovery procedure (O13). Signing an instruction: its recovery service.
- Placing the boundary and finding its fault: the log's axis (`transparency-local` on L0, the monitor's endpoint on L1) and `authority-rules`. Taking it in and the keys it drops: `transparency` and `passkeys`.
- The CLI entry an operator runs it by: once `app-entries`' `reset` shape is there.
- L1's path: its proper way goes to the monitor directly, the embedder reading the key generation in the monitor's signed `stateOf`, checking the receipt, and seeing in `stateOf` that the position took and the generation moved on (procedures §11). This contract is the convenient way while a Core runs; with no answer, the embedder sends directly.
- Showing a holding stance's condition beside the promises' judgment (proposal 544's Operator's): `promises`', which today prints only breaking stances' reasons; the condition is this card's and the stance's reason.

## Offers
- `passkeyReset`, taken only by a module standing on the promises (O1): `reset` (instruction) → the log's `ResetAnswer`; `generation` (subject) → its key generation in the Core's applied state, its flow tended first.
- Composition definition: the contract and its stance (`promises`' `stances`). An opt-in feature: composed only where a composition names it, bringing `transparency` and `passkeys`; never with passkeys alone.

## Invariants
- The reset's path is the one way a subject's last key goes. It holds `front-compromise-new-authorization` only where its caller is the embedder's recovery procedure, on the Core's side alone, never reached from the Front: the operator's condition, its stance's reason.
- A placed reset runs `tend` on the subject's flow and the subject's passkeys' `settle`, then answers; `tend` may stop short of the boundary (64 steps, an unjudged record, another owner's intent), which a later tend takes in. An answer not placed changes nothing. A placed reset is not one that took: the embedder sees it took in `stateOf` (L1) or the key generation moved on (L0).
- Where `tend` or `settle` throws, no answer comes: the same instruction sent again answers as placed and runs both again.
- `generation` tends the subject's flow first and settles where it stepped; it reads the applied state, which may still lag.
- `generation` is the Core's answer, for L0's path alone: on L1 the embedder reads the monitor's signed `stateOf`, since a compromised Core could name a later generation and so hold one valid instruction more.
- On L0 the log is in the Core: an honest Core places and takes a reset in, a compromised one promises nothing (its receipts are unsigned).

## Depends on
- `kernel`, `transparency` (`reset`, `tend`, `ResetAnswer`), `passkeys` (`settle`, `passkeyGenerations`), `promises`, `reset-wire` (the instruction's subject); `zod`.

## Vocabulary
- reset (回復): a subject sent back to the first key's path, its key generation one on. instruction (reset の指示): the embedder's signed request for one.
