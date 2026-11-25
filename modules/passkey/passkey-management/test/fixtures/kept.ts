import type { Kept } from "../../src/contract.ts";

/** A store interface in memory over a clock the test moves: each record lives its lifetime, and a change keeps it. */
export function memoryKept<T>() {
	let now = 0;
	const kept = new Map<string, { value: T; until: number }>();
	const live = (key: string) => {
		const held = kept.get(key);
		return held && held.until > now ? held : undefined;
	};
	const store: Kept<T> = {
		create: async (key, record, lifetimeMs) => {
			if (live(key)) return "exists";
			kept.set(key, { value: structuredClone(record), until: now + lifetimeMs });
			return "created";
		},
		read: async (key) => {
			const held = live(key);
			return held && structuredClone(held.value);
		},
		change: async (key, change) => {
			const held = live(key);
			if (!held) return undefined;
			const next = change(structuredClone(held.value));
			if (next) kept.set(key, { value: structuredClone(next.value), until: held.until });
			return { before: structuredClone(held.value), after: structuredClone(live(key)?.value as T) };
		},
	};
	return {
		store,
		advance: (ms: number) => {
			now += ms;
		},
	};
}
