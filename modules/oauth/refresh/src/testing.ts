import { defineModule, type Module } from "@mod/kernel";
import type { z } from "zod";
import type { section } from "./section.ts";
import { type FamilyRecords, familyRecords, type StoredFamilyRecord } from "./store.ts";

export type RefreshSettings = z.input<typeof section>;

/** The refresh part of a test's configuration. */
export const refreshConfig = (settings: Partial<RefreshSettings> = {}) => ({
	refresh: { ...settings },
});

/** refresh's records in memory, ended by the composition's clock (or the one given), each with its subject, for tests. */
export function familyRecordsInMemory(clock?: () => number): {
	readonly module: Module;
	readonly records: FamilyRecords;
	readonly subjects: () => ReadonlyMap<string, string>;
} {
	let now = clock ?? (() => 0);
	const entries = new Map<string, { value: StoredFamilyRecord; ends: number; subject: string }>();
	const live = (name: string) => {
		const found = entries.get(name);
		return found && found.ends > now() ? found : undefined;
	};
	const records: FamilyRecords = {
		create: async (name, value, lifetimeMs, subject) => {
			if (live(name)) return "exists";
			entries.set(name, { value, ends: now() + lifetimeMs, subject });
			return "created";
		},
		read: async (name) => live(name)?.value,
		change: async (name, change) => {
			const found = live(name);
			if (!found) return undefined;
			const next = change(found.value);
			if (next) entries.set(name, { ...found, value: next.value });
			return { before: found.value, after: next ? next.value : found.value };
		},
	};
	const module = defineModule({ name: "refresh-records", replicaSafe: false, takes: [] }, (m) => [
		m.provide(familyRecords).by((c) => {
			now = clock ?? c.clock.now;
			return records;
		}),
	]);
	return {
		module,
		records,
		subjects: () => new Map([...entries].map(([name, e]) => [name, e.subject])),
	};
}
