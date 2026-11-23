import type { Flow } from "@mod/transparency-wire";
import type { FrameRead, FrameStore, IntentUnit, Json, PartRecord } from "../../src/contract.ts";

/** A frame store in memory, with a store clock a test moves and a write it can run before the next. */
export function memoryFrames(parts: readonly string[]) {
	let now = 0;
	let versions = 0;
	const kept = new Map<string, { readonly value: Json; readonly version: string }>();
	let before: (() => Promise<void> | void) | undefined;
	const keyOf = (unit: IntentUnit | Flow, r?: PartRecord) => {
		if (r && !parts.includes(r.part)) throw new TypeError(`no part ${r.part} is bound`);
		const { of, id } = "flow" in unit ? unit.flow : unit;
		const op = "op" in unit ? `#${unit.op}` : "";
		return `${of}:${id}${op}/${r ? `${r.part}/${r.name}` : "frame"}`;
	};
	const put = (key: string, value: Json) => {
		versions += 1;
		kept.set(key, { value: structuredClone(value), version: `v${versions}` });
	};
	const frames: FrameStore = {
		parts,
		async read(unit, records) {
			const keys = [keyOf(unit), ...records.map((r) => keyOf(unit, r))];
			const entries = keys.map((k) => kept.get(k));
			return {
				unit,
				records,
				frame: entries[0] && structuredClone(entries[0].value),
				held: entries.slice(1).map((e) => e && structuredClone(e.value)),
				now,
				basis: entries.map((e) => e?.version ?? null),
			};
		},
		async write(read: FrameRead, next, deadline) {
			const run = before;
			before = undefined;
			await run?.();
			if (now > deadline) return "late";
			const keys = [keyOf(read.unit), ...read.records.map((r) => keyOf(read.unit, r))];
			const versions = read.basis as readonly (string | null)[];
			if (keys.some((k, i) => (kept.get(k)?.version ?? null) !== versions[i])) return "moved";
			if (next.frame !== undefined) put(keys[0] as string, next.frame);
			next.records.forEach((r, i) => {
				const key = keys[i + 1] as string;
				if (r && "value" in r) put(key, r.value);
				if (r && "remove" in r) kept.delete(key);
			});
			return "written";
		},
	};
	return {
		frames,
		clock: {
			now: () => now,
			set: (t: number) => {
				now = t;
			},
		},
		/** Runs once, just before the next write is judged, as another writer would. */
		beforeWrite(run: () => Promise<void> | void) {
			before = run;
		},
		value: (flow: Flow, r?: PartRecord) => kept.get(keyOf(flow, r))?.value,
		put: (flow: Flow, r: PartRecord, value: Json) => put(keyOf(flow, r), value),
	};
}
