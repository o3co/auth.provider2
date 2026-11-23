# frame-store

Internal module of `transparency`: the frame's store interface over `store`, which a wiring builds.

## Responsibilities
- Keeps a flow's frame and part records under the flow's partition, the frame in the frames' space and each record in its part's, and writes them as one by the store's batch across.

## Not here
- Which space holds the frames, and each part's: the wirings'.

## Offers
- `frameStoreOver` (the store, the frames' space, the parts' places, randomness, the wiring's `refuse`) → `FrameStore`. `frameParts`, the parts' places, keyed by name.

## Invariants
- Refuses through `refuse` a store with no batch across, and a part whose space declares other guarantees than the frames'.
- A write is held to every version read, an absent one too; nothing it writes expires. One whose answer was lost is sent again under its mark, three sends at most.
- A record of a part not bound is a TypeError.

## Depends on
- `kernel` (`isUnavailable`, the point), `store`.
