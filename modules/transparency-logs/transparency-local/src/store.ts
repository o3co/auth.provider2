import type { Random } from "@mod/kernel";
import { type HeldRead, type Place, recordsHeldAcross } from "@mod/records";
import type { Space, Store } from "@mod/store";
import type { Json } from "@mod/transparency";
import type { LogStore } from "./contract.ts";

/**
 * The log's store interface over `records`' records held across, in one space: each key a record
 * of its own, read, then written as one held to every version read. A wiring builds it, naming
 * `where` and its builder's `refuse` for what records held across refuse.
 */
export function logStoreOver(p: {
	readonly store: Store;
	readonly space: Space;
	readonly random: Random;
	readonly where: string;
	readonly refuse: (where: string, reason: string) => never;
}): LogStore {
	const place: Place = { store: p.store, space: p.space, random: p.random };
	const held = recordsHeldAcross([place], p.where, p.refuse);
	return {
		async read(keys) {
			const read = await held.read(keys.map((key) => ({ place, key })));
			return { values: read.values, now: read.now, basis: read };
		},
		write(read, next, deadline) {
			const nexts = next.map((value: Json | undefined) =>
				value === undefined ? undefined : { value, lifetimeMs: "endless" as const },
			);
			return held.write(read.basis as HeldRead, nexts, deadline);
		},
	};
}
