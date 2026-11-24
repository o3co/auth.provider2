import { extensionPoint, type Random } from "@mod/kernel";
import { type HeldRead, type Next, type Place, recordsHeldAcross } from "@mod/records";
import type { Json, Space, Store } from "@mod/store";
import type { FrameStore, IntentUnit, PartNext, PartRecord } from "@mod/transparency";

/**
 * `transparency`'s frame store over `records`: a unit's frame and its parts' records, each a record
 * of its place, read, then written as one by `records`' records held across. Wirings build it.
 */

/** Where a part's records are kept: the space its owner's wiring declares and binds to it. */
export interface FramePart {
	readonly name: string;
	readonly space: Space;
}

/** The parts' places, keyed by part name, each contributed by the wiring of the part's owner. */
export const frameParts = extensionPoint<FramePart>("transparency-frames.parts", {
	multiplicity: "keyed",
	keyOf: (part) => part.name,
});

/** A unit's own words, in order: no two units, and no unit and a part's record, share a key. */
const wordsOf = (unit: IntentUnit) =>
	"op" in unit ? [unit.flow.of, unit.flow.id, unit.op] : [unit.flow.of, unit.flow.id];
const endless = (value: Json): Next<Json> => ({ value, lifetimeMs: "endless" });
/** A key's words as written; none for a key it did not write. */
const wordsIn = (key: string): readonly unknown[] | undefined => {
	try {
		const words: unknown = JSON.parse(key);
		return Array.isArray(words) ? words : undefined;
	} catch {
		return undefined;
	}
};

/**
 * The frame store over `records`, in the frames' space and each part's. Refuses through `refuse`
 * (the wiring's, naming `where`) what records held across cannot hold: a store without a batch
 * across, a part's space of other guarantees than the frames', or one holding a subject's data.
 */
export function frameStoreOver(p: {
	readonly store: Store;
	readonly space: Space;
	readonly parts: readonly FramePart[];
	readonly random: Random;
	readonly where: string;
	readonly refuse: (where: string, reason: string) => never;
}): FrameStore {
	const placeOf = (space: Space): Place => ({ store: p.store, space, random: p.random });
	const framesPlace = placeOf(p.space);
	const places = new Map(p.parts.map((part) => [part.name, placeOf(part.space)]));
	const held = recordsHeldAcross([framesPlace, ...places.values()], p.where, p.refuse);
	/** A client's flow's record: under the flow's words alone, which no unit and no part's record uses. */
	const flowTarget = (flow: IntentUnit["flow"]) => ({
		place: framesPlace,
		key: JSON.stringify([flow.of, flow.id]),
	});
	const targetsOf = (unit: IntentUnit, records: readonly PartRecord[]) => [
		{ place: framesPlace, key: JSON.stringify(wordsOf(unit)) },
		...records.map((r) => {
			const place = places.get(r.part);
			if (!place) throw new TypeError(`transparency-frames: no part ${r.part} is bound`);
			return { place, key: JSON.stringify([...wordsOf(unit), r.part, r.name]) };
		}),
		...("op" in unit ? [flowTarget(unit.flow)] : []),
	];
	return {
		parts: [...places.keys()],
		async read(unit, records) {
			const read = await held.read(targetsOf(unit, records));
			const flow = "op" in unit ? { flow: read.values[records.length + 1] } : {};
			return {
				unit,
				records,
				frame: read.values[0],
				held: read.values.slice(1, records.length + 1),
				now: read.now,
				...flow,
				basis: read,
			};
		},
		async flowRecord(flow) {
			return (await held.read([flowTarget(flow)])).values[0];
		},
		async clientFlows(cursor) {
			const page = await p.store.scan(p.space, cursor);
			const flows = page.keys.flatMap((key) => {
				const words = key.name === "record" ? wordsIn(key.partition) : undefined;
				const [of, id, ...more] = words ?? [];
				return of === "client" && typeof id === "string" && more.length === 0
					? [{ of: "client" as const, id }]
					: [];
			});
			return page.cursor === undefined ? { flows } : { flows, cursor: page.cursor };
		},
		async write(read, next, deadline) {
			const record = (n: PartNext) => (n === undefined || "remove" in n ? n : endless(n.value));
			const frame: PartNext = next.drop
				? { remove: true }
				: next.frame === undefined
					? undefined
					: { value: next.frame };
			const flow: PartNext = next.flow === undefined ? undefined : { value: next.flow };
			const nexts = [
				record(frame),
				...next.records.map(record),
				...("op" in read.unit ? [record(flow)] : []),
			];
			return held.write(read.basis as HeldRead, nexts, deadline);
		},
	};
}
