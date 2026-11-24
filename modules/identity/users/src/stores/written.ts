import { Unavailable } from "@mod/kernel";
import type { Changed, RecordStore } from "../store.ts";

/**
 * Changes the record, or saves `first` where there is none; one saved meanwhile is changed from what it holds.
 */
export async function written<T>(
	store: RecordStore<T>,
	key: string,
	first: T,
	change: (record: T) => Changed<T> | undefined,
): Promise<{ readonly before: T | undefined; readonly after: T }> {
	const changed = await store.update(key, change);
	if (changed) return changed;
	if ((await store.save(key, first, "endless")) === "created")
		return { before: undefined, after: first };
	const again = await store.update(key, change);
	// The key held a record a moment ago, and records never end.
	if (!again) throw new Unavailable("users");
	return again;
}
