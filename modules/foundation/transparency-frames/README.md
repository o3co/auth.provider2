# transparency-frames

## Responsibilities
- Builds `transparency`'s frame store over `records`: a unit's frame and its parts' records, each a record of its place, read, then written as one by `records`' records held across, by the deadline `transparency` gives. A capability like `records`, built by a wiring, never used by a feature.

## Not here
- What a frame and a part's records hold: `transparency` and each part's owner. Which space holds the frames, and each part's: the wirings'.
- Conditional writes, marks, resends, deadlines, and what a store or a space can hold together: `records`.

## Offers
- `frameStoreOver` (the store, the frames' space, the parts' places, randomness, `where`, the wiring's `refuse`) → `transparency`'s `FrameStore`.
- `frameParts`, each part's place (`FramePart`), keyed by part name, which the wiring of the part's owner contributes.

## Invariants
- Refuses through `refuse`, naming `where`, what `records` refuses of records held across: a store with no batch across, a part's space of other guarantees than the frames', and a part's space holding a subject's data, or an index of one.
- A part's space needs no subject writer, as a Step's one write carries none: a part's records are erased by the erasure boundary's Step alone, its state owner's `write` removing them.
- A unit's frame is the record keyed by the unit's words (its flow, and a client's op), a part's record by the unit's words, its part and its name, and a client's flow's record by the flow's words alone, in the frames' space: no two units, parts or flows share a key. Nothing it writes expires but records' own settled marks; a frame a write drops is removed.
- A client's op's read holds its flow's record, and its write is held to it: two ops of one flow writing it race as one record.
- `clientFlows` lists, page by page, the client flows holding a record, by a scan of the frames' space as `store` walks it: a key of a flow's words alone.
- A record of a part not bound is a TypeError.

## Depends on
- `kernel` (the extension point, randomness), `records` (records held across), `store` (its types), `transparency` (the frame store interface).

## Vocabulary
- unit, frame, part: `transparency`'s. place: `records`'.
