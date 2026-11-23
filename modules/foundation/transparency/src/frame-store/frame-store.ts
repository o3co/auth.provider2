import { extensionPoint, isUnavailable, type Random } from "@mod/kernel";
import type { BatchWrite, Condition, Key, Space, Store } from "@mod/store";
import type { FramePart, FrameStore, IntentUnit, PartNext, PartRecord } from "../contract.ts";

/** The parts' places, keyed by part name, each contributed by the wiring of the part's owner. */
export const frameParts = extensionPoint<FramePart>("transparency.frame-parts", {
	multiplicity: "keyed",
	keyOf: (part) => part.name,
});

/** How many times a write whose answer was lost is sent again under its mark. */
const sends = 3;
const sameGuarantees = (a: Space, b: Space) => {
	const set = (s: Space) => JSON.stringify([...new Set(s.guarantees)].sort());
	return set(a) === set(b);
};

/**
 * The frame's store interface over `store`: a flow's frame and its part records under the flow's
 * partition, in the frames' space and each part's, written as one by the store's batch across.
 * Refuses through `refuse` (the wiring's) a store without one, or a part's space of other guarantees.
 */
export function frameStoreOver(p: {
	readonly store: Store;
	readonly space: Space;
	readonly parts: readonly FramePart[];
	readonly random: Random;
	readonly refuse: (where: string, reason: string) => never;
}): FrameStore {
	const where = "transparency-store";
	const across = p.store.batchAcross?.bind(p.store);
	if (!across) {
		return p.refuse(
			where,
			"its store writes no records of two partitions as one, which a Step's one write needs",
		);
	}
	const other = p.parts.find((part) => !sameGuarantees(part.space, p.space));
	if (other) {
		return p.refuse(
			where,
			`part ${other.name} declares other guarantees than the frames, so a fault could keep half a Step`,
		);
	}
	const spaceOf = new Map(p.parts.map((part) => [part.name, part.space]));
	const keyOf = (unit: IntentUnit, r?: PartRecord): Key => {
		const op = "op" in unit ? `\n${unit.op}` : "";
		const partition = `${unit.flow.of}:${unit.flow.id}${op}`;
		if (!r) return { space: p.space, partition, name: "frame" };
		const space = spaceOf.get(r.part);
		if (!space) throw new TypeError(`transparency-store: no part ${r.part} is bound`);
		return { space, partition, name: r.name };
	};
	return {
		parts: [...spaceOf.keys()],
		async read(unit, records) {
			const keys = [keyOf(unit), ...records.map((r) => keyOf(unit, r))];
			const reads = await Promise.all(keys.map((key) => p.store.get(key)));
			return {
				unit,
				records,
				frame: reads[0]?.entry?.value,
				held: reads.slice(1).map((r) => r.entry?.value),
				now: reads[0]?.now ?? 0,
				basis: reads.map((r) => r.entry?.version ?? null),
			};
		},
		async write(read, next, deadline) {
			const keys = [keyOf(read.unit), ...read.records.map((r) => keyOf(read.unit, r))];
			const versions = read.basis as readonly (string | null)[];
			const conditions = keys.map((key, i): Condition => {
				const version = versions[i];
				return version === null || version === undefined ? { key, absent: true } : { key, version };
			});
			const nexts: PartNext[] = [
				next.frame === undefined ? undefined : { value: next.frame },
				...next.records,
			];
			const writes = nexts.flatMap((n, i): BatchWrite[] => {
				const key = keys[i];
				if (!n || !key) return [];
				return "remove" in n
					? [{ key, remove: true }]
					: [{ key, put: n.value, expiry: { kind: "never" } }];
			});
			// Writing nothing confirms the read by a mark of its own, held by the same conditions.
			const [frameKey] = keys;
			if (writes.length === 0 && frameKey) {
				writes.push({
					key: { ...frameKey, name: "settled" },
					put: true,
					expiry: { kind: "after", ms: 1 },
				});
			}
			const idempotency = Buffer.from(p.random.bytes(16)).toString("base64url");
			for (let sent = 1; ; sent++) {
				try {
					const answer = await across(conditions, writes, { deadline, idempotency });
					if (answer.kind === "committed") return "written";
					if (answer.kind === "conflict") return "moved";
					if (answer.kind === "late") return "late";
					throw new Error("transparency-store: a write's own mark came back reused");
				} catch (error) {
					// Unavailable may have applied: the same mark gets the first answer.
					if (!isUnavailable(error) || sent >= sends) throw error;
				}
			}
		},
	};
}
